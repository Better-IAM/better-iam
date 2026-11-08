package server

// Port of packages/server/src/api/billing.ts: the `billing` API group (usage-based billing and spend tracking) and
// `iam.billing`, the trusted runtime. Billing managers (`iam:billing:manage`) define meters and prices for their
// subtree, budgets, and the billing profile; `iam:billing:read` reads spend (by person, team, department, project,
// meter, day or tag), budgets, credits and statements; `iam:billing:record` meters usage (a backend's service
// account). People read their own spend (`mySpend`), team maintainers their team's (`teamSpend`), department heads
// their department's (`departmentSpend`). Credits, period closing and payment status are root-only.

import (
	"context"
	"math"
	"strings"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// BillingAPI is the `billing` API group (packages/server/src/api/billing.ts createBillingApi): every method runs through the
// operation envelope; the router maps POST {basePath}/billing/{method} onto it.
type BillingAPI struct {
	server *ServerContext
}

// CreateBillingAPI builds the `billing` API group.
func CreateBillingAPI(server *ServerContext) *BillingAPI {
	return &BillingAPI{server: server}
}

const maxBudgetsPerTenant = 200

var billingBudgetPeriods = []string{"month", "quarter", "year"}
var billingSubjectTypes = []string{"tenant", "team", "department", "identity"}

// ---------------------------------------------------------------------------------------------------------------
// JavaScript helpers

// billingSort is Array.prototype.sort with a comparator as V8 runs it on short arrays (binary insertion sort): the
// same order as any stable sort for a consistent comparator, and V8's order for the comparators of the TypeScript
// source that never answer 0.
func billingSort[T any](items []T, compare func(a, b T) float64) {
	for index := 1; index < len(items); index++ {
		pivot := items[index]
		left, right := 0, index
		for left < right {
			middle := left + (right-left)/2
			if compare(pivot, items[middle]) < 0 {
				right = middle
			} else {
				left = middle + 1
			}
		}
		copy(items[left+1:index+1], items[left:index])
		items[left] = pivot
	}
}

// billingOr is `a || b` over comparator results: the first truthy number, else the last.
func billingOr(values ...float64) float64 {
	for _, value := range values[:len(values)-1] {
		if value != 0 && !math.IsNaN(value) {
			return value
		}
	}
	return values[len(values)-1]
}

// billingBefore is `a < b ? -1 : 1` for strings.
func billingBefore(a, b any) float64 {
	if billingLess(a, b) {
		return -1
	}
	return 1
}

// billingLess is JavaScript `a < b` for two strings.
func billingLess(a, b any) bool {
	x, ok := a.(string)
	y, ok2 := b.(string)
	if !ok || !ok2 {
		return jsNumber(a) < jsNumber(b)
	}
	return compareUTF16(x, y) < 0
}

// billingByName is `(a, b) => a.name.localeCompare(b.name)`.
func billingByName(a, b *core.Object) float64 {
	return float64(localeCompare(jsString(a.Get("name")), jsString(b.Get("name"))))
}

// billingNum is Number(record[key]).
func billingNum(record *core.Object, key string) float64 { return jsNumber(record.Get(key)) }

// billingStr is String(record[key]).
func billingStr(record *core.Object, key string) string { return jsString(record.Get(key)) }

// billingList is a list of records as a model array.
func billingList(items []*core.Object) []any {
	out := make([]any, len(items))
	for index, item := range items {
		out[index] = item
	}
	return out
}

// billingRecords is a model array of records (anything else is skipped).
func billingRecords(value any) []*core.Object {
	list, _ := value.([]any)
	out := make([]*core.Object, 0, len(list))
	for _, item := range list {
		if record, ok := item.(*core.Object); ok && record != nil {
			out = append(out, record)
		}
	}
	return out
}

// billingWithout is `const { a: _a, b: _b, ...rest } = record`.
func billingWithout(record *core.Object, keys ...string) *core.Object {
	rest := record.Spread()
	for _, key := range keys {
		rest.Delete(key)
	}
	return rest
}

// billingMathRound is Math.round: halves round toward +Infinity.
func billingMathRound(value float64) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return value
	}
	floor := math.Floor(value)
	if value-floor >= 0.5 {
		return floor + 1
	}
	return floor
}

// billingSortedUnique is `[...new Set(items)].sort()`.
func billingSortedUnique(items []string) []any {
	list := unique(items)
	billingSort(list, func(a, b string) float64 { return float64(compareUTF16(a, b)) })
	return stringsOf(list)
}

// billingCalc runs the billing arithmetic, keeping the first error (the arithmetic helpers of billing.ts are
// infallible in TypeScript; their Go counterparts answer an error while their module is unported).
type billingCalc struct{ err error }

func (c *billingCalc) keep(err error) {
	if c.err == nil && err != nil {
		c.err = err
	}
}

func (c *billingCalc) units(micros any) float64 {
	value, err := UnitsOf(jsNumber(micros))
	c.keep(err)
	return value
}

func (c *billingCalc) round(value float64) float64 {
	result, err := RoundMicros(value)
	c.keep(err)
	return result
}

func (c *billingCalc) due(statement *core.Object) float64 {
	value, err := AmountDue(statement)
	c.keep(err)
	return value
}

func (c *billingCalc) paid(statement *core.Object) float64 {
	value, err := AmountPaid(statement)
	c.keep(err)
	return value
}

func (c *billingCalc) publicPrice(spec any) *core.Object {
	record, _ := spec.(*core.Object)
	value, err := PublicPriceSpec(record)
	c.keep(err)
	return value
}

// billingSum is `items.reduce((sum, item) => sum + item[key], 0)`.
func billingSum(items []*core.Object, key string) float64 {
	sum := 0.0
	for _, item := range items {
		sum += billingNum(item, key)
	}
	return sum
}

// ---------------------------------------------------------------------------------------------------------------
// Views

// billingTermsView is termsView: a billing account's contract terms as the API shows them.
func billingTermsView(accountID string, terms *core.Object, showSetBy bool) (*core.Object, error) {
	calc := &billingCalc{}
	view := core.NewObject("accountId", accountID, "inherited", false)
	if value := terms.Get("discountPercent"); !isUndefined(value) {
		view.Set("discountPercent", value)
	}
	if value := terms.Get("minimumCommitmentMicros"); !isUndefined(value) {
		view.Set("minimumCommitmentMicros", value)
		view.Set("minimumCommitment", calc.units(value))
	}
	if value := terms.Get("taxRatePercent"); !isUndefined(value) {
		view.Set("taxRatePercent", value)
	}
	if value := terms.Get("taxLabel"); !isUndefined(value) {
		view.Set("taxLabel", value)
	}
	if terms != nil {
		view.Set("setAt", terms.Get("setAt"))
	}
	if terms != nil && showSetBy {
		view.Set("setBy", terms.Get("setBy"))
	}
	return view, calc.err
}

// billingSummary is summary: a statement as lists show it.
func billingSummary(statement *core.Object, now int64, tenantName any) (*core.Object, error) {
	calc := &billingCalc{}
	view := core.NewObject("id", statement.Get("id"), "tenantId", statement.Get("tenantId"))
	if !isUndefined(tenantName) {
		view.Set("tenantName", tenantName)
	}
	due := calc.due(statement)
	view.Set("number", statement.Get("number")).
		Set("period", statement.Get("period")).
		Set("status", statement.Get("status")).
		Set("currency", statement.Get("currency")).
		Set("subtotalMicros", statement.Get("subtotalMicros")).
		Set("creditsMicros", statement.Get("creditsMicros")).
		Set("totalMicros", statement.Get("totalMicros")).
		Set("total", calc.units(statement.Get("totalMicros"))).
		Set("amountPaidMicros", calc.paid(statement)).
		Set("amountDueMicros", due).
		Set("amountDue", calc.units(due))
	if value := statement.Get("creditNotesMicros"); truthy(value) {
		view.Set("creditNotesMicros", value)
	}
	view.Set("billingReason", coalesce(statement.Get("billingReason"), "period")).
		Set("issuedAt", statement.Get("issuedAt")).
		Set("dueAt", statement.Get("dueAt"))
	if value := statement.Get("paidAt"); !isUndefined(value) {
		view.Set("paidAt", value)
	}
	view.Set("overdue", statement.Get("status") == "finalized" && billingNum(statement, "dueAt") < float64(now) && due > 0)
	return view, calc.err
}

// billingCreditView is creditView.
func billingCreditView(credit *core.Object, now int64) (*core.Object, error) {
	calc := &billingCalc{}
	view := core.NewObject("id", credit.Get("id"), "tenantId", credit.Get("tenantId"),
		"amountMicros", credit.Get("amountMicros"), "amount", calc.units(credit.Get("amountMicros")),
		"remainingMicros", credit.Get("remainingMicros"), "remaining", calc.units(credit.Get("remainingMicros")),
		"reason", credit.Get("reason"))
	if value := credit.Get("expiresAt"); !isUndefined(value) {
		view.Set("expiresAt", value)
	}
	view.Set("grantedAt", credit.Get("grantedAt")).Set("grantedBy", credit.Get("grantedBy"))
	if value := credit.Get("revokedAt"); !isUndefined(value) {
		view.Set("revokedAt", value)
	}
	expiresAt := credit.Get("expiresAt")
	view.Set("active", isUndefined(credit.Get("revokedAt")) && billingNum(credit, "remainingMicros") > 0 &&
		(isUndefined(expiresAt) || jsNumber(expiresAt) > float64(now)))
	return view, calc.err
}

// billingInvoiceItemView is invoiceItemView.
func billingInvoiceItemView(item *core.Object) (*core.Object, error) {
	calc := &billingCalc{}
	view := core.NewObject("id", item.Get("id"), "accountId", item.Get("tenantId"), "description", item.Get("description"),
		"quantity", item.Get("quantity"), "unitAmountMicros", item.Get("unitAmountMicros"),
		"unitAmount", calc.units(item.Get("unitAmountMicros")), "amountMicros", item.Get("amountMicros"),
		"amount", calc.units(item.Get("amountMicros")))
	if value := item.Get("period"); !isUndefined(value) {
		view.Set("period", value)
	}
	view.Set("status", item.Get("status"))
	if value := item.Get("statementId"); !isUndefined(value) {
		view.Set("statementId", value)
	}
	view.Set("source", item.Get("source"))
	if value := item.Get("subscriptionId"); !isUndefined(value) {
		view.Set("subscriptionId", value)
	}
	if value := item.Get("metadata"); !isUndefined(value) {
		view.Set("metadata", value)
	}
	view.Set("createdAt", item.Get("createdAt")).Set("createdBy", item.Get("createdBy"))
	return view, calc.err
}

// billingInvoiceItemViews maps invoice items to their views.
func billingInvoiceItemViews(items []*core.Object) ([]any, error) {
	out := make([]any, len(items))
	for index, item := range items {
		view, err := billingInvoiceItemView(item)
		if err != nil {
			return nil, err
		}
		out[index] = view
	}
	return out, nil
}

// billingCreditNoteView is creditNoteView.
func billingCreditNoteView(note *core.Object) (*core.Object, error) {
	calc := &billingCalc{}
	view := core.NewObject("id", note.Get("id"), "accountId", note.Get("tenantId"), "number", note.Get("number"),
		"statementId", note.Get("statementId"), "statementNumber", note.Get("statementNumber"),
		"amountMicros", note.Get("amountMicros"), "amount", calc.units(note.Get("amountMicros")),
		"reason", note.Get("reason"))
	if value := note.Get("memo"); !isUndefined(value) {
		view.Set("memo", value)
	}
	view.Set("applied", note.Get("applied"))
	if value := note.Get("creditId"); !isUndefined(value) {
		view.Set("creditId", value)
	}
	view.Set("issuedAt", note.Get("issuedAt")).Set("issuedBy", note.Get("issuedBy"))
	return view, calc.err
}

// billingPlanView is planView; subscribers is core.Undefined to leave the count out.
func billingPlanView(plan *core.Object, subscribers any) (*core.Object, error) {
	calc := &billingCalc{}
	view := core.NewObject("id", plan.Get("id"), "key", plan.Get("key"), "name", plan.Get("name"))
	if value := plan.Get("description"); !isUndefined(value) {
		view.Set("description", value)
	}
	items := []any{}
	for _, item := range billingRecords(plan.Get("items")) {
		entry := core.NewObject("id", item.Get("id"), "kind", item.Get("kind"), "name", item.Get("name"))
		if value := item.Get("amountMicros"); !isUndefined(value) {
			entry.Set("amount", jsNumber(value)/1_000_000)
		}
		if value := item.Get("unitAmountMicros"); !isUndefined(value) {
			entry.Set("unitAmount", jsNumber(value)/1_000_000)
		}
		if value := item.Get("includedSeats"); !isUndefined(value) {
			entry.Set("includedSeats", value)
		}
		if item.Get("kind") != "usage" {
			entry.Set("billing", coalesce(item.Get("billing"), "advance"))
		}
		if value := item.Get("meter"); !isUndefined(value) {
			entry.Set("meter", value)
		}
		if value := item.Get("price"); truthy(value) {
			entry.Set("price", calc.publicPrice(value))
		}
		items = append(items, entry)
	}
	view.Set("items", items)
	if value := plan.Get("trialDays"); !isUndefined(value) {
		view.Set("trialDays", value)
	}
	view.Set("selfServe", plan.Get("selfServe")).Set("archived", plan.Get("archived"))
	if !isUndefined(subscribers) {
		view.Set("subscribers", subscribers)
	}
	view.Set("createdAt", plan.Get("createdAt")).Set("updatedAt", plan.Get("updatedAt"))
	return view, calc.err
}

// billingSubscriptionView is subscriptionView.
func billingSubscriptionView(subscription *core.Object, now int64, accountName any) (*core.Object, error) {
	view := core.NewObject("id", subscription.Get("id"), "accountId", subscription.Get("tenantId"))
	if !isUndefined(accountName) {
		view.Set("accountName", accountName)
	}
	status, err := SubscriptionStatus(subscription, now)
	if err != nil {
		return nil, err
	}
	view.Set("planId", subscription.Get("planId")).
		Set("planKey", subscription.Get("planKey")).
		Set("planName", subscription.Get("planName")).
		Set("status", status).
		Set("startedAt", subscription.Get("startedAt"))
	if value := subscription.Get("trialEndsAt"); !isUndefined(value) {
		view.Set("trialEndsAt", value)
	}
	if value := subscription.Get("endsAt"); !isUndefined(value) {
		view.Set("endsAt", value)
	}
	view.Set("cancelAtPeriodEnd", subscription.Get("cancelAtPeriodEnd"))
	if value := subscription.Get("canceledAt"); !isUndefined(value) {
		view.Set("canceledAt", value)
	}
	view.Set("seats", subscription.Get("seats")).
		Set("billedAdvance", subscription.Get("billedAdvance")).
		Set("createdAt", subscription.Get("createdAt")).
		Set("createdBy", subscription.Get("createdBy"))
	return view, nil
}

// billingCouponView is couponView.
func billingCouponView(coupon *core.Object, now int64) (*core.Object, error) {
	calc := &billingCalc{}
	view := core.NewObject("id", coupon.Get("id"), "code", coupon.Get("code"), "name", coupon.Get("name"))
	if value := coupon.Get("percentOff"); !isUndefined(value) {
		view.Set("percentOff", value)
	}
	if value := coupon.Get("amountOffMicros"); !isUndefined(value) {
		view.Set("amountOffMicros", value)
		view.Set("amountOff", calc.units(value))
	}
	view.Set("duration", coupon.Get("duration"))
	if value := coupon.Get("durationInMonths"); !isUndefined(value) {
		view.Set("durationInMonths", value)
	}
	if value := coupon.Get("maxRedemptions"); !isUndefined(value) {
		view.Set("maxRedemptions", value)
	}
	view.Set("redemptions", coupon.Get("redemptions"))
	if value := coupon.Get("redeemBy"); !isUndefined(value) {
		view.Set("redeemBy", value)
	}
	redeemBy, maxRedemptions := coupon.Get("redeemBy"), coupon.Get("maxRedemptions")
	view.Set("active", truthy(coupon.Get("active")) &&
		(isUndefined(redeemBy) || jsNumber(redeemBy) > float64(now)) &&
		(isUndefined(maxRedemptions) || billingNum(coupon, "redemptions") < jsNumber(maxRedemptions)))
	view.Set("createdAt", coupon.Get("createdAt"))
	return view, calc.err
}

// billingDiscountView is discountView.
func billingDiscountView(discount *core.Object, period string, timeZone string) (*core.Object, error) {
	calc := &billingCalc{}
	view := core.NewObject("id", discount.Get("id"), "accountId", discount.Get("tenantId"),
		"couponId", discount.Get("couponId"), "code", discount.Get("code"), "name", discount.Get("name"))
	if value := discount.Get("percentOff"); !isUndefined(value) {
		view.Set("percentOff", value)
	}
	if value := discount.Get("amountOffMicros"); !isUndefined(value) {
		view.Set("amountOffMicros", value)
		view.Set("amountOff", calc.units(value))
	}
	view.Set("duration", discount.Get("duration"))
	if value := discount.Get("durationInMonths"); !isUndefined(value) {
		view.Set("durationInMonths", value)
	}
	view.Set("appliedInvoices", discount.Get("appliedInvoices")).
		Set("redeemedAt", discount.Get("redeemedAt")).
		Set("redeemedBy", discount.Get("redeemedBy"))
	if value := discount.Get("endedAt"); !isUndefined(value) {
		view.Set("endedAt", value)
	}
	if calc.err != nil {
		return nil, calc.err
	}
	active, err := DiscountActive(discount, period, timeZone)
	if err != nil {
		return nil, err
	}
	view.Set("active", active)
	return view, nil
}

// billingPriceView is priceView; targetName is core.Undefined to leave the tenant name out.
func billingPriceView(price *core.Object, showSetBy bool, targetName any) (*core.Object, error) {
	calc := &billingCalc{}
	view := core.NewObject("meter", price.Get("meter"), "targetTenantId", price.Get("tenantId"))
	if !isUndefined(targetName) {
		view.Set("targetTenantName", targetName)
	}
	view.Set("definerId", price.Get("definerId")).
		Set("effectiveFrom", price.Get("effectiveFrom")).
		Set("price", calc.publicPrice(price.Get("spec")))
	if value := price.Get("note"); !isUndefined(value) {
		view.Set("note", value)
	}
	view.Set("setAt", price.Get("setAt"))
	if showSetBy {
		view.Set("setBy", price.Get("setBy"))
	}
	return view, calc.err
}

// ---------------------------------------------------------------------------------------------------------------
// Private helpers of createBillingApi

// service is billingServiceOf(ctx).
func (api *BillingAPI) service() *BillingService { return BillingServiceOf(api.server) }

// settings is the billing service's settings (currency, time zone, ...).
func (api *BillingAPI) settings() *core.Object { return api.service().Settings }

// billingWritable refuses changes to a deleted tenant.
func billingWritable(realm *core.Object) error {
	if realm.Get("status") == "deleted" {
		return core.NewIamError("INVALID_TRANSITION", "Deleted tenants cannot be updated")
	}
	return nil
}

// ownMeter is a meter the tenant itself defines (NOT_FOUND otherwise).
func (api *BillingAPI) ownMeter(ctx context.Context, tx core.IamStore, tenantID any, key string) (*core.Object, error) {
	found, err := tx.Find(ctx, BillingCollections.Meters, core.NewObject("tenantId", tenantID, "uniqueKey", key), nil)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, core.NewIamError("NOT_FOUND", "Billing meter not found", 404)
	}
	return found[0], nil
}

// audit records an allowed billing event.
func (api *BillingAPI) audit(ctx context.Context, tx core.IamStore, principal *Principal, action string, tenantID any, resourceID string, metadata *core.Object) error {
	return api.server.Events.Audit(ctx, tx, principal, action, jsString(tenantID), resourceID, "allow", false, metadata)
}

// effectivePrice is the price chain for a tenant's account: from the account up, or from the tenant for meters
// defined inside it.
func (api *BillingAPI) effectivePrice(ctx context.Context, tx core.IamStore, realm, meter *core.Object, period string) (*core.Object, error) {
	server := api.server
	account, err := AccountOf(ctx, server, tx, realm)
	if err != nil {
		return nil, err
	}
	accountChain, err := server.Ancestry(ctx, tx, account)
	if err != nil {
		return nil, err
	}
	chain := accountChain
	inChain := false
	for _, tenant := range accountChain {
		if tenant.Get("id") == meter.Get("tenantId") {
			inChain = true
			break
		}
	}
	if !inChain {
		if chain, err = server.Ancestry(ctx, tx, realm); err != nil {
			return nil, err
		}
	}
	return PriceFor(ctx, tx, meter, chain, period)
}

// seesPriceSetter is whether the caller sees who set a meter's prices: people of the tenant that defines the meter
// and of the tenants above it. Below, a platform meter's prices would name root administrators.
func (api *BillingAPI) seesPriceSetter(ctx context.Context, tx core.IamStore, principal *Principal, meter *core.Object) (bool, error) {
	ids, err := api.server.AncestorIDs(ctx, tx, billingStr(meter, "tenantId"))
	if err != nil {
		return false, err
	}
	tenantID, ok := principal.Identity.Get("tenantId").(string)
	return ok && containsString(ids, tenantID), nil
}

// meterView is a meter as a tenant sees it.
func (api *BillingAPI) meterView(ctx context.Context, tx core.IamStore, realm, meter *core.Object, rootID any, principal *Principal) (*core.Object, error) {
	var price *core.Object
	if meter.Get("pricing") == "rate-card" {
		period, err := api.service().CurrentPeriod()
		if err != nil {
			return nil, err
		}
		if price, err = api.effectivePrice(ctx, tx, realm, meter, period); err != nil {
			return nil, err
		}
	}
	view := core.NewObject("key", meter.Get("key"), "name", meter.Get("name"), "unit", meter.Get("unit"))
	if value := meter.Get("description"); !isUndefined(value) {
		view.Set("description", value)
	}
	scope := "tenant"
	if meter.Get("tenantId") == rootID {
		scope = "platform"
	}
	view.Set("aggregation", meter.Get("aggregation")).
		Set("pricing", meter.Get("pricing")).
		Set("archived", meter.Get("archived")).
		Set("definedBy", meter.Get("tenantId")).
		Set("scope", scope).
		Set("inherited", meter.Get("tenantId") != realm.Get("id"))
	if price != nil {
		sees, err := api.seesPriceSetter(ctx, tx, principal, meter)
		if err != nil {
			return nil, err
		}
		priceView, err := billingPriceView(price, sees, core.Undefined)
		if err != nil {
			return nil, err
		}
		view.Set("price", priceView)
	}
	view.Set("createdAt", meter.Get("createdAt")).Set("updatedAt", meter.Get("updatedAt"))
	return view, nil
}

// inSubtree is whether a tenant is the realm or below it.
func (api *BillingAPI) inSubtree(ctx context.Context, tx core.IamStore, realm *core.Object, tenantID any) (bool, error) {
	id, ok := tenantID.(string)
	if !ok {
		id = jsString(tenantID)
	}
	ids, err := api.server.AncestorIDs(ctx, tx, id)
	if err != nil {
		return false, err
	}
	realmID, _ := realm.Get("id").(string)
	return containsString(ids, realmID), nil
}

// billingReadOutcome is the outcome of a readAs transaction: a refusal is returned rather than failed, so the
// transaction commits the recorded decision.
type billingReadOutcome struct {
	denied bool
	value  *core.Object
}

// readAs is a read allowed by `iam:billing:read` or by a role the caller holds over the data (team maintainer,
// department head): `via` names that role or answers "". The role counts only for a person signed in as themselves
// in their own tenant; impersonation, delegated, role-session and API-key credentials read through the permission.
func (api *BillingAPI) readAs(ctx context.Context, credential core.CredentialInput, tenantID any, resourceID string,
	via func(ctx context.Context, tx core.IamStore, principal *Principal, realm *core.Object) (string, error),
	fn func(ctx context.Context, tx core.IamStore, realm *core.Object) (*core.Object, error)) (*core.Object, error) {
	server := api.server
	target, err := Text(tenantID, "tenantId")
	if err != nil {
		return nil, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return nil, err
	}
	outcome, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (billingReadOutcome, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return billingReadOutcome{}, err
		}
		realm, err := server.Tenant(ctx, tx, target)
		if err != nil {
			return billingReadOutcome{}, err
		}
		session, identity := principal.Session, principal.Identity
		ownSession := session.Get("kind") == "user" &&
			ActsInOwnRight(session) &&
			!truthy(session.Get("impersonatorId")) &&
			strictEquals(session.Get("tenantId"), identity.Get("tenantId")) &&
			identity.Get("kind") == "user"
		role := ""
		if ownSession {
			if role, err = via(ctx, tx, principal, realm); err != nil {
				return billingReadOutcome{}, err
			}
		}
		if role == "" {
			decision, err := server.Operations.RecordedDecision(ctx, tx, principal, AuthorizationRequest{
				TenantID: billingStr(realm, "id"), Action: "iam:billing:read", Resource: ResourceTarget{Type: "iam", ID: resourceID},
			})
			if err != nil {
				return billingReadOutcome{}, err
			}
			if !decision.Allowed {
				return billingReadOutcome{denied: true}, nil
			}
		}
		value, err := fn(ctx, tx, realm)
		if err != nil {
			return billingReadOutcome{}, err
		}
		through := role
		if through == "" {
			through = "permission"
		}
		if err := api.audit(ctx, tx, principal, "iam:billing:read", realm.Get("id"), resourceID, core.NewObject("via", through)); err != nil {
			return billingReadOutcome{}, err
		}
		return billingReadOutcome{value: value}, nil
	})
	if err != nil {
		return nil, err
	}
	if outcome.denied {
		return nil, core.NewIamError("ACCESS_DENIED", "Access denied", 403)
	}
	return outcome.value, nil
}

// budgetView is a budget's settings with its current standing.
func (api *BillingAPI) budgetView(ctx context.Context, tx core.IamStore, budget *core.Object) (*core.Object, error) {
	status, err := api.service().BudgetStatus(ctx, tx, budget, nil)
	if err != nil {
		return nil, err
	}
	return status.Spread().
		Set("forecastAlerts", budget.Get("forecastAlerts")).
		Set("notify", budget.Get("notify")).
		Set("createdAt", budget.Get("createdAt")).
		Set("createdBy", budget.Get("createdBy")).
		Set("updatedAt", budget.Get("updatedAt")), nil
}

// budgetSubject validates a budget subject against the budget's tenant.
func (api *BillingAPI) budgetSubject(ctx context.Context, tx core.IamStore, realm *core.Object, kind any, subjectID any) (*core.Object, error) {
	server := api.server
	subjectType, ok := coalesce(kind, "tenant").(string)
	if !ok || !containsString(billingSubjectTypes, subjectType) {
		return nil, invalidInput("subjectType must be 'tenant', 'team', 'department' or 'identity'")
	}
	inScope := func(tenantID any) (bool, error) {
		inside, err := api.inSubtree(ctx, tx, realm, tenantID)
		if err != nil || inside {
			return inside, err
		}
		ids, err := server.AncestorIDs(ctx, tx, billingStr(realm, "id"))
		if err != nil {
			return false, err
		}
		id, isString := tenantID.(string)
		return isString && containsString(ids, id), nil
	}
	if subjectType == "tenant" {
		target := realm
		if !isUndefined(subjectID) {
			id, err := Text(subjectID, "subjectId")
			if err != nil {
				return nil, err
			}
			if target, err = server.Tenant(ctx, tx, id); err != nil {
				return nil, err
			}
		}
		inside, err := api.inSubtree(ctx, tx, realm, target.Get("id"))
		if err != nil {
			return nil, err
		}
		if !inside {
			return nil, invalidInput("A tenant budget covers this tenant or one below it")
		}
		return core.NewObject("subjectType", subjectType, "subjectId", target.Get("id")), nil
	}
	value, err := Text(subjectID, "subjectId")
	if err != nil {
		return nil, err
	}
	switch subjectType {
	case "identity":
		identity, err := tx.Get(ctx, "identities", value)
		if err != nil {
			return nil, err
		}
		found := identity != nil && identity.Get("status") != "deleted"
		if found {
			if found, err = api.inSubtree(ctx, tx, realm, identity.Get("tenantId")); err != nil {
				return nil, err
			}
		}
		if !found {
			return nil, core.NewIamError("NOT_FOUND", "Identity not found", 404)
		}
	case "team":
		team, err := tx.Get(ctx, "teams", value)
		if err != nil {
			return nil, err
		}
		found := team != nil
		if found {
			if found, err = inScope(team.Get("tenantId")); err != nil {
				return nil, err
			}
		}
		if !found {
			return nil, core.NewIamError("NOT_FOUND", "Team not found", 404)
		}
	default:
		department, err := tx.Get(ctx, "departments", value)
		if err != nil {
			return nil, err
		}
		found := department != nil
		if found {
			if found, err = inScope(department.Get("tenantId")); err != nil {
				return nil, err
			}
		}
		if !found {
			return nil, core.NewIamError("NOT_FOUND", "Department not found", 404)
		}
	}
	return core.NewObject("subjectType", subjectType, "subjectId", value), nil
}

// billingFlag is a boolean setting: the fallback when left out, INVALID_INPUT when not a boolean.
func billingFlag(value any, fallback any, field string) (any, error) {
	if isUndefined(value) {
		return fallback, nil
	}
	if _, ok := value.(bool); !ok {
		return nil, invalidInput(field + " must be a boolean")
	}
	return value, nil
}

// budgetSettings is the validated budget settings; current (nil for a new budget) supplies values an update leaves
// out.
func budgetSettings(input *core.Object, current *core.Object) (*core.Object, error) {
	var name any = current.Get("name")
	if value := input.Get("name"); !isUndefined(value) {
		text, err := Text(value, "name", 128)
		if err != nil {
			return nil, err
		}
		name = core.JSTrim(text)
	}
	if !truthy(name) {
		return nil, invalidInput("name is required")
	}
	var amount any = current.Get("amountMicros")
	if value := input.Get("amount"); !isUndefined(value) {
		micros, err := AmountMicros(value, "amount")
		if err != nil {
			return nil, err
		}
		amount = micros
	}
	if !truthy(amount) || jsNumber(amount) <= 0 {
		return nil, invalidInput("amount must be above 0")
	}
	period := coalesce(input.Get("period"), coalesce(current.Get("period"), "month"))
	if text, ok := period.(string); !ok || !containsString(billingBudgetPeriods, text) {
		return nil, invalidInput("period must be 'month', 'quarter' or 'year'")
	}
	meters := current.Get("meters")
	if value := input.Get("meters"); value == nil {
		meters = core.Undefined
	} else if !isUndefined(value) {
		list, ok := value.([]any)
		if !ok || len(list) == 0 || len(list) > 20 {
			return nil, invalidInput("meters must list 1-20 meter keys")
		}
		keys := make([]string, len(list))
		for index, item := range list {
			key, err := MeterKey(item)
			if err != nil {
				return nil, err
			}
			keys[index] = key
		}
		meters = billingSortedUnique(keys)
	}
	var thresholds any
	if isUndefined(input.Get("thresholds")) && current != nil {
		thresholds = current.Get("thresholds")
	} else {
		values, err := BudgetThresholds(input.Get("thresholds"))
		if err != nil {
			return nil, err
		}
		list := make([]any, len(values))
		for index, value := range values {
			list[index] = value
		}
		thresholds = list
	}
	notifyInput := core.NewObject()
	if value := input.Get("notify"); !isUndefined(value) {
		object, err := Object(value)
		if err != nil {
			return nil, err
		}
		notifyInput = object
	}
	currentNotify, _ := current.Get("notify").(*core.Object)
	var emails any
	if value := notifyInput.Get("emails"); isUndefined(value) {
		emails = coalesce(member(current.Get("notify"), "emails"), []any{})
	} else {
		list, ok := value.([]any)
		if !ok || len(list) > 10 {
			return nil, invalidInput("notify.emails must list at most 10 addresses")
		}
		addresses := make([]string, len(list))
		for index, item := range list {
			address, err := Email(item)
			if err != nil {
				return nil, err
			}
			addresses[index] = address
		}
		emails = billingSortedUnique(addresses)
	}
	forecastAlerts, err := billingFlag(input.Get("forecastAlerts"), coalesce(current.Get("forecastAlerts"), true), "forecastAlerts")
	if err != nil {
		return nil, err
	}
	owners, err := billingFlag(notifyInput.Get("owners"), coalesce(currentNotify.Get("owners"), true), "notify.owners")
	if err != nil {
		return nil, err
	}
	subject, err := billingFlag(notifyInput.Get("subject"), coalesce(currentNotify.Get("subject"), true), "notify.subject")
	if err != nil {
		return nil, err
	}
	enforce, err := billingFlag(input.Get("enforce"), coalesce(current.Get("enforce"), false), "enforce")
	if err != nil {
		return nil, err
	}
	fields := core.NewObject("name", name, "amountMicros", amount, "period", period)
	if truthy(meters) {
		fields.Set("meters", meters)
	}
	return fields.Set("thresholds", thresholds).
		Set("forecastAlerts", forecastAlerts).
		Set("notify", core.NewObject("owners", owners, "subject", subject, "emails", emails)).
		Set("enforce", enforce), nil
}

// ownBudget is a budget of the tenant.
func (api *BillingAPI) ownBudget(ctx context.Context, tx core.IamStore, tenantID any, budgetID any) (*core.Object, error) {
	id, err := Text(budgetID, "budgetId")
	if err != nil {
		return nil, err
	}
	return api.server.Scoped(ctx, tx, BillingCollections.Budgets, id, jsString(tenantID))
}

// scopeStatements is the statements of the accounts in a tenant's subtree (every statement for the root).
func (api *BillingAPI) scopeStatements(ctx context.Context, tx core.IamStore, realm *core.Object) ([]*core.Object, error) {
	if realm.Get("parentId") == nil {
		return tx.Find(ctx, BillingCollections.Statements, nil, nil)
	}
	tenants, err := Subtree(ctx, api.server, tx, realm)
	if err != nil {
		return nil, err
	}
	result := []*core.Object{}
	for _, tenant := range tenants {
		found, err := tx.Find(ctx, BillingCollections.Statements, core.NewObject("tenantId", tenant.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		result = append(result, found...)
	}
	return result, nil
}

// scopedStatement is a statement of an account in the tenant's subtree.
func (api *BillingAPI) scopedStatement(ctx context.Context, tx core.IamStore, realm *core.Object, statementID any) (*core.Object, error) {
	id, err := Text(statementID, "statementId")
	if err != nil {
		return nil, err
	}
	statement, err := tx.Get(ctx, BillingCollections.Statements, id)
	if err != nil {
		return nil, err
	}
	found := statement != nil
	if found {
		if found, err = api.inSubtree(ctx, tx, realm, statement.Get("tenantId")); err != nil {
			return nil, err
		}
	}
	if !found {
		return nil, core.NewIamError("NOT_FOUND", "Statement not found", 404)
	}
	return statement, nil
}

// profileTarget is the tenant a profile call is about: the operation's tenant, or `targetTenantId` below it.
func (api *BillingAPI) profileTarget(ctx context.Context, tx core.IamStore, realm *core.Object, targetTenantID any) (*core.Object, error) {
	if isUndefined(targetTenantID) {
		return realm, nil
	}
	id, err := Text(targetTenantID, "targetTenantId")
	if err != nil {
		return nil, err
	}
	target, err := api.server.Tenant(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	inside, err := api.inSubtree(ctx, tx, realm, target.Get("id"))
	if err != nil {
		return nil, err
	}
	if !inside {
		return nil, core.NewIamError("NOT_FOUND", "Tenant not found", 404)
	}
	return target, nil
}

// profileView is a tenant's billing profile and the account that pays for it.
func (api *BillingAPI) profileView(ctx context.Context, tx core.IamStore, target *core.Object, profile *core.Object) (*core.Object, error) {
	account, err := AccountOf(ctx, api.server, tx, target)
	if err != nil {
		return nil, err
	}
	var fields any
	if profile != nil {
		fields = billingWithout(profile, "id", "tenantId", "uniqueKey")
	}
	return core.NewObject(
		"tenantId", target.Get("id"),
		"account", core.NewObject("id", account.Get("id"), "name", account.Get("name"), "inherited", account.Get("id") != target.Get("id")),
		"profile", fields,
	), nil
}

// ownAccount is the tenant as a billing account: invoices, subscriptions and discounts belong to accounts.
func (api *BillingAPI) ownAccount(ctx context.Context, tx core.IamStore, realm *core.Object) (*core.Object, error) {
	account, err := AccountOf(ctx, api.server, tx, realm)
	if err != nil {
		return nil, err
	}
	if account.Get("id") != realm.Get("id") || realm.Get("parentId") == nil {
		return nil, invalidInput("Only a billing account (an organization or a tenant with a profile) has invoices and subscriptions")
	}
	return account, nil
}

// billingOnRoot refuses platform objects (plans, coupons) outside the root tenant.
func billingOnRoot(realm *core.Object, what string) error {
	if realm.Get("parentId") != nil {
		return invalidInput(what + " are managed on the platform (root) tenant")
	}
	return nil
}

// rootOf is the root tenant above the realm.
func (api *BillingAPI) rootOf(ctx context.Context, tx core.IamStore, realm *core.Object) (*core.Object, error) {
	chain, err := api.server.Ancestry(ctx, tx, realm)
	if err != nil {
		return nil, err
	}
	for _, tenant := range chain {
		if tenant.Get("parentId") == nil {
			return tenant, nil
		}
	}
	return realm, nil
}

// planByRef is a platform plan by id or key.
func (api *BillingAPI) planByRef(ctx context.Context, tx core.IamStore, realm *core.Object, ref any) (*core.Object, error) {
	value, err := Text(ref, "plan", 128)
	if err != nil {
		return nil, err
	}
	root, err := api.rootOf(ctx, tx, realm)
	if err != nil {
		return nil, err
	}
	plans, err := tx.Find(ctx, BillingCollections.Plans, core.NewObject("tenantId", root.Get("id")), nil)
	if err != nil {
		return nil, err
	}
	for _, candidate := range plans {
		if candidate.Get("id") == value || candidate.Get("key") == value {
			return candidate, nil
		}
	}
	return nil, core.NewIamError("NOT_FOUND", "Billing plan not found", 404)
}

// mayManage is whether the caller is a root administrator: account billing managers act on self-serve plans only.
func (api *BillingAPI) mayManage(ctx context.Context, tx core.IamStore, principal *Principal, plans ...*core.Object) (bool, error) {
	root, err := api.server.RootPrincipal(ctx, tx, principal)
	if err != nil || root {
		return root, err
	}
	for _, plan := range plans {
		if !truthy(plan.Get("selfServe")) {
			return false, NewOperationDenied("Only root administrators manage subscriptions to plans that are not self-serve")
		}
	}
	return false, nil
}

// coveredAccounts is the ids of the billing accounts a tenant's reads cover (nil: every account, for the root).
func (api *BillingAPI) coveredAccounts(ctx context.Context, tx core.IamStore, realm *core.Object) (map[string]bool, error) {
	if realm.Get("parentId") == nil {
		return nil, nil
	}
	tenants, err := Subtree(ctx, api.server, tx, realm)
	if err != nil {
		return nil, err
	}
	covered := map[string]bool{}
	for _, tenant := range tenants {
		covered[billingStr(tenant, "id")] = true
	}
	return covered, nil
}

// billingCovers is `!covered || covered.has(tenantId)`.
func billingCovers(covered map[string]bool, tenantID any) bool {
	if covered == nil {
		return true
	}
	id, ok := tenantID.(string)
	return ok && covered[id]
}

// tenantName is `(await tx.get('tenants', id))?.name`.
func billingTenantName(ctx context.Context, tx core.IamStore, tenantID any) (any, error) {
	id, ok := tenantID.(string)
	if !ok {
		return core.Undefined, nil
	}
	tenant, err := tx.Get(ctx, "tenants", id)
	if err != nil || tenant == nil {
		return core.Undefined, err
	}
	return tenant.Get("name"), nil
}

// accountStatement is an invoice of the tenant's own account or, called on the root tenant, of any account.
func (api *BillingAPI) accountStatement(ctx context.Context, tx core.IamStore, realm *core.Object, statementID any) (*core.Object, error) {
	id, err := Text(statementID, "statementId")
	if err != nil {
		return nil, err
	}
	statement, err := tx.Get(ctx, BillingCollections.Statements, id)
	if err != nil {
		return nil, err
	}
	if statement == nil || (statement.Get("tenantId") != realm.Get("id") && realm.Get("parentId") != nil) {
		return nil, core.NewIamError("NOT_FOUND", "Statement not found", 404)
	}
	return statement, nil
}

// summaryOf is summary with the account's name.
func (api *BillingAPI) summaryOf(ctx context.Context, tx core.IamStore, statement *core.Object) (*core.Object, error) {
	name, err := billingTenantName(ctx, tx, statement.Get("tenantId"))
	if err != nil {
		return nil, err
	}
	return billingSummary(statement, api.server.Now(), name)
}

// lastChainID is `chain.at(-1)!.id`.
func billingRootID(chain []*core.Object) any {
	if len(chain) == 0 {
		return core.Undefined
	}
	return chain[len(chain)-1].Get("id")
}

// prorationMicros is the rounded sum of proration items.
func billingProration(items []*core.Object) (float64, error) {
	return RoundMicros(billingSum(items, "amountMicros"))
}

// ---------------------------------------------------------------------------------------------------------------
// Meters and prices

// ListMeters is POST {basePath}/billing/listMeters. The meters that reach the tenant (its own and those of its
// ancestors), with the price that applies to the tenant's billing account this period. Requires iam:billing:read.
func (api *BillingAPI) ListMeters(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingListMetersInput]) (Out[apitypes.BillingListMetersOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:read", "billing",
		func(ctx context.Context, call MutationContext) ([]any, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			chain, err := server.Ancestry(ctx, tx, realm)
			if err != nil {
				return nil, err
			}
			rootID := billingRootID(chain)
			meters, err := MetersFor(ctx, tx, chain)
			if err != nil {
				return nil, err
			}
			list := make([]*core.Object, 0, len(meters))
			for _, meter := range meters {
				list = append(list, meter)
			}
			billingSort(list, func(a, b *core.Object) float64 { return billingBefore(a.Get("key"), b.Get("key")) })
			views := []any{}
			for _, meter := range list {
				view, err := api.meterView(ctx, tx, realm, meter, rootID, principal)
				if err != nil {
					return nil, err
				}
				views = append(views, view)
			}
			return views, nil
		}, false)
	return Out[apitypes.BillingListMetersOutput]{Value: result}, err
}

// CreateMeter is POST {basePath}/billing/createMeter. Defines a meter: on the root tenant a platform meter billed to
// every organization, elsewhere a meter for the tenant's own subtree (chargeback: it shows in spend but never on a
// platform statement). Keys may not repeat a key an ancestor defines; at most 100 meters per tenant. Requires
// iam:billing:manage on `iam/billing/meters/{key}`; audited as `billing:meter-create`.
func (api *BillingAPI) CreateMeter(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingCreateMeterInput]) (Out[apitypes.BillingCreateMeterOutput], error) {
	server := api.server
	key, err := MeterKey(input.Get("key"))
	if err != nil {
		return Out[apitypes.BillingCreateMeterOutput]{}, err
	}
	resource := "billing/meters/" + key
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", resource,
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := billingWritable(realm); err != nil {
				return nil, err
			}
			body, err := Object(input.Body)
			if err != nil {
				return nil, err
			}
			fields, err := MeterSettings(billingWithout(body, "tenantId", "key", "archived"), nil)
			if err != nil {
				return nil, err
			}
			chain, err := server.Ancestry(ctx, tx, realm)
			if err != nil {
				return nil, err
			}
			// Built-in meters (`inference`) are the platform's: other modules bill through them.
			if realm.Get("parentId") != nil {
				builtIn, err := BuiltInMeterKey(key)
				if err != nil {
					return nil, err
				}
				if builtIn {
					return nil, core.NewIamError("CONFLICT", key+" is a built-in platform meter", 409)
				}
			}
			existing, err := ResolveMeter(ctx, tx, chain, key)
			if err != nil {
				return nil, err
			}
			if existing != nil {
				return nil, core.NewIamError("CONFLICT", "A meter with this key already reaches this tenant", 409)
			}
			own, err := tx.Find(ctx, BillingCollections.Meters, core.NewObject("tenantId", realm.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			if len(own) >= MaxMetersPerTenant {
				return nil, core.NewIamError("LIMIT_EXCEEDED", "A tenant can define at most "+jsString(float64(MaxMetersPerTenant))+" meters", 409)
			}
			now := server.Now()
			actor := principal.Identity.Get("id")
			record := core.NewObject("id", ID(), "tenantId", realm.Get("id"), "uniqueKey", key, "key", key)
			record.Assign(fields)
			record.Set("archived", false).Set("createdAt", now).Set("createdBy", actor).Set("updatedAt", now).Set("updatedBy", actor)
			meter, err := tx.Insert(ctx, BillingCollections.Meters, record)
			if err != nil {
				return nil, err
			}
			if err := api.audit(ctx, tx, principal, "billing:meter-create", realm.Get("id"), resource, core.NewObject(
				"key", key, "name", meter.Get("name"), "unit", meter.Get("unit"),
				"aggregation", meter.Get("aggregation"), "pricing", meter.Get("pricing"),
			)); err != nil {
				return nil, err
			}
			return api.meterView(ctx, tx, realm, meter, billingRootID(chain), principal)
		}, false)
	return Out[apitypes.BillingCreateMeterOutput]{Value: result}, err
}

// UpdateMeter is POST {basePath}/billing/updateMeter. Renames a meter, changes its unit or description (`null`
// clears it), or archives it (`archived: true` refuses new usage and keeps its history). Aggregation and pricing
// cannot change. Requires iam:billing:manage; audited as `billing:meter-update`.
func (api *BillingAPI) UpdateMeter(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingUpdateMeterInput]) (Out[apitypes.BillingUpdateMeterOutput], error) {
	server := api.server
	key, err := MeterKey(input.Get("key"))
	if err != nil {
		return Out[apitypes.BillingUpdateMeterOutput]{}, err
	}
	resource := "billing/meters/" + key
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", resource,
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := billingWritable(realm); err != nil {
				return nil, err
			}
			meter, err := api.ownMeter(ctx, tx, realm.Get("id"), key)
			if err != nil {
				return nil, err
			}
			body, err := Object(input.Body)
			if err != nil {
				return nil, err
			}
			fields, err := MeterSettings(billingWithout(body, "tenantId", "key"), meter)
			if err != nil {
				return nil, err
			}
			record := billingWithout(meter, "description").Assign(fields)
			record.Set("updatedAt", server.Now()).Set("updatedBy", principal.Identity.Get("id"))
			next, err := tx.Put(ctx, BillingCollections.Meters, record)
			if err != nil {
				return nil, err
			}
			if err := api.audit(ctx, tx, principal, "billing:meter-update", realm.Get("id"), resource, core.NewObject(
				"key", key, "name", next.Get("name"), "unit", next.Get("unit"), "archived", next.Get("archived"),
			)); err != nil {
				return nil, err
			}
			chain, err := server.Ancestry(ctx, tx, realm)
			if err != nil {
				return nil, err
			}
			return api.meterView(ctx, tx, realm, next, billingRootID(chain), principal)
		}, false)
	return Out[apitypes.BillingUpdateMeterOutput]{Value: result}, err
}

// DeleteMeter is POST {basePath}/billing/deleteMeter. Deletes a meter that has never recorded usage, with its
// prices; a meter with history can only be archived (RESOURCE_IN_USE). Requires iam:billing:manage; audited as
// `billing:meter-delete`.
func (api *BillingAPI) DeleteMeter(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingDeleteMeterInput]) (Out[apitypes.BillingDeleteMeterOutput], error) {
	server := api.server
	key, err := MeterKey(input.Get("key"))
	if err != nil {
		return Out[apitypes.BillingDeleteMeterOutput]{}, err
	}
	resource := "billing/meters/" + key
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", resource,
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			meter, err := api.ownMeter(ctx, tx, realm.Get("id"), key)
			if err != nil {
				return nil, err
			}
			one := 1
			rollups, err := tx.Find(ctx, BillingCollections.Rollups, core.NewObject("meterId", meter.Get("id")), &core.FindOptions{Limit: &one})
			if err != nil {
				return nil, err
			}
			if len(rollups) > 0 {
				return nil, core.NewIamError("RESOURCE_IN_USE", "This meter has recorded usage; archive it instead", 409)
			}
			prices, err := tx.Find(ctx, BillingCollections.Prices, core.NewObject("meterId", meter.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			for _, price := range prices {
				if err := tx.Delete(ctx, BillingCollections.Prices, billingStr(price, "id")); err != nil {
					return nil, err
				}
			}
			if err := tx.Delete(ctx, BillingCollections.Meters, billingStr(meter, "id")); err != nil {
				return nil, err
			}
			removed := float64(len(prices))
			if err := api.audit(ctx, tx, principal, "billing:meter-delete", realm.Get("id"), resource,
				core.NewObject("key", key, "removedPrices", removed)); err != nil {
				return nil, err
			}
			return core.NewObject("success", true, "removedPrices", removed), nil
		}, false)
	return Out[apitypes.BillingDeleteMeterOutput]{Value: result}, err
}

// SetPrice is POST {basePath}/billing/setPrice. Sets a rate-card price for a meter this tenant defines: its list
// price (on the tenant itself) or a negotiated price for a tenant below it (`targetTenantId`, applying to that
// subtree). `effectiveFrom` (default the current period; up to 12 periods back while none of them is invoiced for
// the tenants it reaches) starts it; the latest entry effective by a period prices it. `price: null` removes the
// entry. Requires iam:billing:manage; audited as `billing:price`.
func (api *BillingAPI) SetPrice(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingSetPriceInput]) (Out[apitypes.BillingSetPriceOutput], error) {
	server := api.server
	key, err := MeterKey(input.Get("meter"))
	if err != nil {
		return Out[apitypes.BillingSetPriceOutput]{}, err
	}
	resource := "billing/meters/" + key
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", resource,
		func(ctx context.Context, call MutationContext) (any, error) {
			tx, definer, principal := call.Tx, call.Tenant, call.Principal
			meter, err := api.ownMeter(ctx, tx, definer.Get("id"), key)
			if err != nil {
				return nil, err
			}
			if meter.Get("pricing") != "rate-card" {
				return nil, invalidInput("Reported meters carry their cost on each event")
			}
			target := definer
			if value := input.Get("targetTenantId"); !isUndefined(value) {
				id, err := Text(value, "targetTenantId")
				if err != nil {
					return nil, err
				}
				if target, err = server.Tenant(ctx, tx, id); err != nil {
					return nil, err
				}
			}
			inside, err := api.inSubtree(ctx, tx, definer, target.Get("id"))
			if err != nil {
				return nil, err
			}
			if !inside {
				return nil, invalidInput("targetTenantId must be the defining tenant or a tenant below it")
			}
			current, err := api.service().CurrentPeriod()
			if err != nil {
				return nil, err
			}
			effectiveFrom := current
			if value := input.Get("effectiveFrom"); !isUndefined(value) {
				if effectiveFrom, err = BillingPeriod(value, "effectiveFrom"); err != nil {
					return nil, err
				}
			}
			if compareUTF16(effectiveFrom, current) < 0 {
				// A past period may still be priced (usage recorded before its price was set) until it is invoiced.
				earliest, err := ShiftPeriod(current, -12)
				if err != nil {
					return nil, err
				}
				if compareUTF16(effectiveFrom, earliest) < 0 {
					return nil, invalidInput("effectiveFrom may reach back at most 12 periods")
				}
				tenants, err := Subtree(ctx, server, tx, target)
				if err != nil {
					return nil, err
				}
				affected := map[string]bool{}
				for _, tenant := range tenants {
					affected[billingStr(tenant, "id")] = true
				}
				account, err := AccountOf(ctx, server, tx, target)
				if err != nil {
					return nil, err
				}
				affected[billingStr(account, "id")] = true
				statements, err := tx.Find(ctx, BillingCollections.Statements, nil, nil)
				if err != nil {
					return nil, err
				}
				for _, statement := range statements {
					status := statement.Get("status")
					period, _ := statement.Get("period").(string)
					tenantID, _ := statement.Get("tenantId").(string)
					if status != "void" && status != "draft" && !billingLess(period, effectiveFrom) && affected[tenantID] {
						return nil, core.NewIamError("BILLING_PERIOD_CLOSED", "A period from effectiveFrom on has already been invoiced; invoiced periods keep their prices", 409)
					}
				}
			}
			uniqueKey := billingStr(meter, "id") + ":" + effectiveFrom
			found, err := tx.Find(ctx, BillingCollections.Prices, core.NewObject("tenantId", target.Get("id"), "uniqueKey", uniqueKey), nil)
			if err != nil {
				return nil, err
			}
			var existing *core.Object
			if len(found) > 0 {
				existing = found[0]
			}
			if input.Get("price") == nil {
				if existing != nil {
					if err := tx.Delete(ctx, BillingCollections.Prices, billingStr(existing, "id")); err != nil {
						return nil, err
					}
				}
				if err := api.audit(ctx, tx, principal, "billing:price", definer.Get("id"), resource, core.NewObject(
					"meter", key, "targetTenantId", target.Get("id"), "effectiveFrom", effectiveFrom, "price", nil,
				)); err != nil {
					return nil, err
				}
				return nil, nil
			}
			if err := billingWritable(target); err != nil {
				return nil, err
			}
			spec, err := PriceSpec(input.Get("price"))
			if err != nil {
				return nil, err
			}
			var id any = ID()
			if existing != nil {
				id = existing.Get("id")
			}
			entry := core.NewObject("id", id, "tenantId", target.Get("id"), "uniqueKey", uniqueKey, "meterId", meter.Get("id"),
				"meter", key, "definerId", definer.Get("id"), "effectiveFrom", effectiveFrom, "spec", spec)
			if value := input.Get("note"); !isUndefined(value) {
				note, err := Text(value, "note", 512)
				if err != nil {
					return nil, err
				}
				entry.Set("note", core.JSTrim(note))
			}
			entry.Set("setAt", server.Now()).Set("setBy", principal.Identity.Get("id"))
			if existing != nil {
				_, err = tx.Put(ctx, BillingCollections.Prices, entry)
			} else {
				_, err = tx.Insert(ctx, BillingCollections.Prices, entry)
			}
			if err != nil {
				return nil, err
			}
			if err := api.audit(ctx, tx, principal, "billing:price", definer.Get("id"), resource, core.NewObject(
				"meter", key, "targetTenantId", target.Get("id"), "effectiveFrom", effectiveFrom, "model", spec.Get("model"),
			)); err != nil {
				return nil, err
			}
			return billingPriceView(entry, true, target.Get("name"))
		}, false)
	return Out[apitypes.BillingSetPriceOutput]{Value: result}, err
}

// ListPrices is POST {basePath}/billing/listPrices. A meter's rate card as the tenant may see it: entries for the
// tenant, its ancestors (list prices) and tenants below it (newest first), and the entry that prices the tenant's
// account this period. Requires iam:billing:read.
func (api *BillingAPI) ListPrices(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingListPricesInput]) (Out[apitypes.BillingListPricesOutput], error) {
	server := api.server
	key, err := MeterKey(input.Get("meter"))
	if err != nil {
		return Out[apitypes.BillingListPricesOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:read", "billing/meters/"+key,
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			chain, err := server.Ancestry(ctx, tx, realm)
			if err != nil {
				return nil, err
			}
			meter, err := ResolveMeter(ctx, tx, chain, key)
			if err != nil {
				return nil, err
			}
			if meter == nil {
				return nil, core.NewIamError("NOT_FOUND", "Billing meter not found", 404)
			}
			visible := map[string]bool{}
			for _, tenant := range chain {
				visible[billingStr(tenant, "id")] = true
			}
			below, err := Subtree(ctx, server, tx, realm)
			if err != nil {
				return nil, err
			}
			for _, tenant := range below {
				visible[billingStr(tenant, "id")] = true
			}
			showSetBy, err := api.seesPriceSetter(ctx, tx, principal, meter)
			if err != nil {
				return nil, err
			}
			prices, err := tx.Find(ctx, BillingCollections.Prices, core.NewObject("meterId", meter.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			entries := []*core.Object{}
			for _, price := range prices {
				tenantID, _ := price.Get("tenantId").(string)
				if !visible[tenantID] {
					continue
				}
				name, err := billingTenantName(ctx, tx, price.Get("tenantId"))
				if err != nil {
					return nil, err
				}
				view, err := billingPriceView(price, showSetBy, name)
				if err != nil {
					return nil, err
				}
				entries = append(entries, view)
			}
			billingSort(entries, func(a, b *core.Object) float64 {
				first := 0.0
				if billingLess(a.Get("effectiveFrom"), b.Get("effectiveFrom")) {
					first = 1
				} else if billingLess(b.Get("effectiveFrom"), a.Get("effectiveFrom")) {
					first = -1
				}
				return billingOr(first, billingNum(b, "setAt")-billingNum(a, "setAt"))
			})
			var effective *core.Object
			if meter.Get("pricing") == "rate-card" {
				period, err := api.service().CurrentPeriod()
				if err != nil {
					return nil, err
				}
				if effective, err = api.effectivePrice(ctx, tx, realm, meter, period); err != nil {
					return nil, err
				}
			}
			meterView, err := api.meterView(ctx, tx, realm, meter, billingRootID(chain), principal)
			if err != nil {
				return nil, err
			}
			out := core.NewObject("meter", meterView, "entries", billingList(entries))
			if effective != nil {
				view, err := billingPriceView(effective, showSetBy, core.Undefined)
				if err != nil {
					return nil, err
				}
				out.Set("effective", view)
			}
			return out, nil
		}, false)
	return Out[apitypes.BillingListPricesOutput]{Value: result}, err
}

// Quote is POST {basePath}/billing/quote. What `quantity` units of a meter cost the tenant's billing account in a
// period (default: the current one), as a period total with tiers and included units applied. Requires
// iam:billing:read.
func (api *BillingAPI) Quote(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingQuoteInput]) (Out[apitypes.BillingQuoteOutput], error) {
	server := api.server
	key, err := MeterKey(input.Get("meter"))
	if err != nil {
		return Out[apitypes.BillingQuoteOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:read", "billing/meters/"+key,
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			quantity, ok := core.Normalize(input.Get("quantity")).(float64)
			if !ok || math.IsNaN(quantity) || math.IsInf(quantity, 0) || quantity < 0 {
				return nil, invalidInput("quantity must be a number of at least 0")
			}
			period, err := api.periodOrCurrent(input.Get("period"))
			if err != nil {
				return nil, err
			}
			chain, err := server.Ancestry(ctx, tx, realm)
			if err != nil {
				return nil, err
			}
			meter, err := ResolveMeter(ctx, tx, chain, key)
			if err != nil {
				return nil, err
			}
			if meter == nil {
				return nil, core.NewIamError("NOT_FOUND", "Billing meter not found", 404)
			}
			if meter.Get("pricing") != "rate-card" {
				return nil, invalidInput("Reported meters carry their cost on each event")
			}
			price, err := api.effectivePrice(ctx, tx, realm, meter, period)
			if err != nil {
				return nil, err
			}
			amount := 0.0
			if price != nil {
				spec, _ := price.Get("spec").(*core.Object)
				if amount, err = PriceQuantity(spec, quantity); err != nil {
					return nil, err
				}
			}
			units, err := UnitsOf(amount)
			if err != nil {
				return nil, err
			}
			out := core.NewObject("meter", key, "quantity", quantity, "period", period, "currency", api.settings().Get("currency"),
				"amountMicros", amount, "amount", units)
			if price != nil {
				sees, err := api.seesPriceSetter(ctx, tx, principal, meter)
				if err != nil {
					return nil, err
				}
				view, err := billingPriceView(price, sees, core.Undefined)
				if err != nil {
					return nil, err
				}
				out.Set("price", view)
			} else {
				out.Set("unpriced", true)
			}
			return out, nil
		}, false)
	return Out[apitypes.BillingQuoteOutput]{Value: result}, err
}

// periodOrCurrent is `period === undefined ? service.currentPeriod() : billingPeriod(period)`.
func (api *BillingAPI) periodOrCurrent(value any) (string, error) {
	if isUndefined(value) {
		return api.service().CurrentPeriod()
	}
	return BillingPeriod(value, "period")
}

// ---------------------------------------------------------------------------------------------------------------
// Usage

// Record is POST {basePath}/billing/record. Records usage of a meter in the tenant, attributed to `identityId` (and
// their teams and department at that moment, or `teamId`), with optional `tags`. `idempotencyKey` makes retries safe
// (a repeat returns the first receipt with `duplicate: true`). Reported meters need `cost` (currency units).
// `enforceBudgets` refuses with SPEND_LIMIT_REACHED (402) once an enforced budget covering the usage is spent. Usage
// for a period already invoiced fails with BILLING_PERIOD_CLOSED. Requires iam:billing:record on
// `iam/billing/meters/{key}`.
func (api *BillingAPI) Record(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingRecordInput]) (Out[apitypes.BillingRecordOutput], error) {
	server := api.server
	key, err := MeterKey(input.Get("meter"))
	if err != nil {
		return Out[apitypes.BillingRecordOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:record", "billing/meters/"+key,
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			extra := core.NewObject()
			if input.Get("enforceBudgets") == true {
				extra.Set("enforceBudgets", true)
			}
			return api.service().Record(ctx, call.Tx, input.Body, billingStr(call.Principal.Identity, "id"), extra)
		}, false)
	return Out[apitypes.BillingRecordOutput]{Value: result}, err
}

// RecordMany is POST {basePath}/billing/recordMany. Records up to 100 events in one transaction (all or nothing),
// each in `tenantId` or a tenant below it (their own `tenantId`, default the call's). Requires iam:billing:record in
// `tenantId`.
func (api *BillingAPI) RecordMany(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingRecordManyInput]) (Out[apitypes.BillingRecordManyOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:record", "billing",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			events, ok := input.Get("events").([]any)
			if !ok || len(events) == 0 || len(events) > 100 {
				return nil, invalidInput("events must list 1-100 usage events")
			}
			receipts := []any{}
			for _, raw := range events {
				event, err := Object(raw)
				if err != nil {
					return nil, err
				}
				var tenantID any = realm.Get("id")
				if value := event.Get("tenantId"); !isUndefined(value) {
					text, err := Text(value, "tenantId")
					if err != nil {
						return nil, err
					}
					tenantID = text
				}
				if tenantID != realm.Get("id") {
					inside, err := api.inSubtree(ctx, tx, realm, tenantID)
					if err != nil {
						return nil, err
					}
					if !inside {
						return nil, invalidInput("Every event must be in this tenant or one below it")
					}
				}
				receipt, err := api.service().Record(ctx, tx, event.Spread(core.NewObject("tenantId", tenantID)), billingStr(principal.Identity, "id"), core.NewObject())
				if err != nil {
					return nil, err
				}
				receipts = append(receipts, receipt)
			}
			return core.NewObject("receipts", receipts), nil
		}, false)
	return Out[apitypes.BillingRecordManyOutput]{Value: result}, err
}

// ListUsage is POST {basePath}/billing/listUsage. Raw usage events recorded in this tenant (not its subtree) for a
// period (default current), newest first, optionally for one meter or identity; at most `limit` (1-500, default
// 100). Requires iam:billing:read.
func (api *BillingAPI) ListUsage(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingListUsageInput]) (Out[apitypes.BillingListUsageOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:read", "billing",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm := call.Tx, call.Tenant
			period, err := api.periodOrCurrent(input.Get("period"))
			if err != nil {
				return nil, err
			}
			limit, err := Integer(coalesce(input.Get("limit"), 100.0), "limit", 1, 500)
			if err != nil {
				return nil, err
			}
			var meter any = core.Undefined
			if value := input.Get("meter"); !isUndefined(value) {
				key, err := MeterKey(value)
				if err != nil {
					return nil, err
				}
				meter = key
			}
			var identityID any = core.Undefined
			if value := input.Get("identityId"); !isUndefined(value) {
				text, err := Text(value, "identityId")
				if err != nil {
					return nil, err
				}
				identityID = text
			}
			records, err := tx.Find(ctx, BillingCollections.Usage, core.NewObject("tenantId", realm.Get("id"), "period", period), nil)
			if err != nil {
				return nil, err
			}
			matching := []*core.Object{}
			for _, record := range records {
				if (isUndefined(meter) || record.Get("meter") == meter) &&
					(isUndefined(identityID) || record.Get("identityId") == identityID || record.Get("agentId") == identityID) {
					matching = append(matching, record)
				}
			}
			billingSort(matching, func(a, b *core.Object) float64 {
				return billingOr(billingNum(b, "occurredAt")-billingNum(a, "occurredAt"), billingBefore(a.Get("id"), b.Get("id")))
			})
			if len(matching) > int(limit) {
				matching = matching[:int(limit)]
			}
			events := []any{}
			for _, record := range matching {
				event := billingWithout(record, "rollupId", "expiresAt", "uniqueKey")
				if uniqueKey, ok := record.Get("uniqueKey").(string); ok && strings.HasPrefix(uniqueKey, "idem:") {
					event.Set("idempotencyKey", uniqueKey[5:])
				}
				events = append(events, event)
			}
			return core.NewObject("tenantId", realm.Get("id"), "period", period, "events", events), nil
		}, false)
	return Out[apitypes.BillingListUsageOutput]{Value: result}, err
}

// ---------------------------------------------------------------------------------------------------------------
// Spend

// Spend is POST {basePath}/billing/spend. Spend of the tenant and every tenant below it in a period (default
// current), grouped by `meter` (default), `identity`, `agent`, `team`, `department`, `tenant`, `day` or
// `tag:{name}`, optionally filtered to a meter, identity, team, department or sub-tenant. Each meter's period total
// is priced within its billing account and shared out by quantity, so groups add up to the account's charges. The
// current period carries a linear `forecast`. Requires iam:billing:read.
func (api *BillingAPI) Spend(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingSpendInput]) (Out[apitypes.BillingSpendOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:read", "billing",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			return api.service().Report(ctx, call.Tx, call.Tenant, billingWithout(input.Body, "tenantId"), nil, nil)
		}, false)
	return Out[apitypes.BillingSpendOutput]{Value: result}, err
}

// Trend is POST {basePath}/billing/trend. Monthly totals for the last `months` periods (1-24, default 6), with the
// same filters as `spend`.
func (api *BillingAPI) Trend(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingTrendInput]) (Out[apitypes.BillingTrendOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:read", "billing",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			return api.service().Trend(ctx, call.Tx, call.Tenant, billingWithout(input.Body, "tenantId"), nil)
		}, false)
	return Out[apitypes.BillingTrendOutput]{Value: result}, err
}

// MySpend is POST {basePath}/billing/mySpend. The caller's own spend (their usage and that of the agents they
// sponsor) in their tenant and the tenants below it, grouped by `meter` (default), `day`, `agent`, `tenant` or
// `tag:{name}`, with the budgets set on them. Any credential of the tenant; needs no permission.
func (api *BillingAPI) MySpend(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingMySpendInput]) (Out[apitypes.BillingMySpendOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.BillingMySpendOutput]{}, err
	}
	groupBy := coalesce(input.Get("groupBy"), "meter")
	group, ok := groupBy.(string)
	if !ok || (!containsString([]string{"meter", "day", "agent", "tenant"}, group) && !strings.HasPrefix(group, "tag:")) {
		return Out[apitypes.BillingMySpendOutput]{}, invalidInput("groupBy must be 'meter', 'day', 'agent', 'tenant' or 'tag:{name}'")
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.BillingMySpendOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if principal.Session.Get("tenantId") != tenantID || principal.Identity.Get("tenantId") != tenantID {
			return nil, core.NewIamError("ACCESS_DENIED", "Spend is read in the credential’s own tenant", 403)
		}
		realm, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		service := api.service()
		ownIDs, err := service.OwnIdentities(ctx, tx, principal.Identity)
		if err != nil {
			return nil, err
		}
		own := map[string]bool{}
		for _, id := range ownIDs {
			own[id] = true
		}
		query := core.NewObject("groupBy", group)
		if value := input.Get("period"); !isUndefined(value) {
			query.Set("period", value)
		}
		report, err := service.Report(ctx, tx, realm, query, map[string]any{}, func(row *core.Object) bool {
			identityID, isIdentity := row.Get("identityId").(string)
			agentID, isAgent := row.Get("agentId").(string)
			return (isIdentity && own[identityID]) || (isAgent && own[agentID])
		})
		if err != nil {
			return nil, err
		}
		chain, err := server.Ancestry(ctx, tx, realm)
		if err != nil {
			return nil, err
		}
		budgets := []any{}
		for _, tenant := range chain {
			found, err := tx.Find(ctx, BillingCollections.Budgets, core.NewObject(
				"tenantId", tenant.Get("id"), "subjectType", "identity", "subjectId", principal.Identity.Get("id"),
			), nil)
			if err != nil {
				return nil, err
			}
			for _, budget := range found {
				status, err := service.BudgetStatus(ctx, tx, budget, nil)
				if err != nil {
					return nil, err
				}
				budgets = append(budgets, status)
			}
		}
		return report.Spread().Set("budgets", budgets), nil
	})
	return Out[apitypes.BillingMySpendOutput]{Value: result}, err
}

// spendQuery is a team or department report query: the filter, `groupBy` (default identity) and `period`.
func billingSpendQuery(input *core.Object, filter string, id string) *core.Object {
	query := core.NewObject(filter, id, "groupBy", coalesce(input.Get("groupBy"), "identity"))
	if value := input.Get("period"); !isUndefined(value) {
		query.Set("period", value)
	}
	return query
}

// TeamSpend is POST {basePath}/billing/teamSpend. A team's spend (with the teams below it), grouped by `identity`
// (default), `meter`, `team`, `agent`, `day` or `tag:{name}`. Allowed to the team's maintainers (and those of teams
// above it) or with iam:billing:read.
func (api *BillingAPI) TeamSpend(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingTeamSpendInput]) (Out[apitypes.BillingTeamSpendOutput], error) {
	server := api.server
	teamID, err := Text(input.Get("teamId"), "teamId")
	if err != nil {
		return Out[apitypes.BillingTeamSpendOutput]{}, err
	}
	result, err := api.readAs(ctx, credential, input.Get("tenantId"), "billing/teams/"+teamID,
		func(ctx context.Context, tx core.IamStore, principal *Principal, realm *core.Object) (string, error) {
			team, err := tx.Get(ctx, "teams", teamID)
			if err != nil {
				return "", err
			}
			// Maintainers read in the team's own tenant (or a project below it), never elsewhere.
			if team == nil || principal.Identity.Get("tenantId") != team.Get("tenantId") {
				return "", nil
			}
			ids, err := server.AncestorIDs(ctx, tx, billingStr(realm, "id"))
			if err != nil {
				return "", err
			}
			teamTenant, _ := team.Get("tenantId").(string)
			if !containsString(ids, teamTenant) {
				return "", nil
			}
			maintainer, err := IsTeamMaintainer(ctx, tx, teamTenant, billingStr(team, "id"), billingStr(principal.Identity, "id"),
				core.NewObject("at", server.Now(), "includeAncestors", true))
			if err != nil || !maintainer {
				return "", err
			}
			return "team-maintainer", nil
		},
		func(ctx context.Context, tx core.IamStore, realm *core.Object) (*core.Object, error) {
			return api.service().Report(ctx, tx, realm, billingSpendQuery(input.Body, "teamId", teamID), nil, nil)
		})
	return Out[apitypes.BillingTeamSpendOutput]{Value: result}, err
}

// DepartmentSpend is POST {basePath}/billing/departmentSpend. A department's spend (with the departments below it),
// grouped by `identity` (default), `department`, `team`, `meter`, `day` or `tag:{name}`. Allowed to the
// department's head (and heads above it) or with iam:billing:read.
func (api *BillingAPI) DepartmentSpend(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingDepartmentSpendInput]) (Out[apitypes.BillingDepartmentSpendOutput], error) {
	server := api.server
	departmentID, err := Text(input.Get("departmentId"), "departmentId")
	if err != nil {
		return Out[apitypes.BillingDepartmentSpendOutput]{}, err
	}
	result, err := api.readAs(ctx, credential, input.Get("tenantId"), "billing/departments/"+departmentID,
		func(ctx context.Context, tx core.IamStore, principal *Principal, realm *core.Object) (string, error) {
			department, err := tx.Get(ctx, "departments", departmentID)
			if err != nil {
				return "", err
			}
			if department == nil || principal.Identity.Get("tenantId") != department.Get("tenantId") {
				return "", nil
			}
			ids, err := server.AncestorIDs(ctx, tx, billingStr(realm, "id"))
			if err != nil {
				return "", err
			}
			departmentTenant, _ := department.Get("tenantId").(string)
			if !containsString(ids, departmentTenant) {
				return "", nil
			}
			heads, err := DepartmentHeads(ctx, tx, departmentTenant, billingStr(department, "id"), core.NewObject("includeAncestors", true))
			if err != nil {
				return "", err
			}
			identityID, _ := principal.Identity.Get("id").(string)
			if containsString(heads, identityID) {
				return "department-head", nil
			}
			return "", nil
		},
		func(ctx context.Context, tx core.IamStore, realm *core.Object) (*core.Object, error) {
			return api.service().Report(ctx, tx, realm, billingSpendQuery(input.Body, "departmentId", departmentID), nil, nil)
		})
	return Out[apitypes.BillingDepartmentSpendOutput]{Value: result}, err
}

// Accounts is POST {basePath}/billing/accounts. The billing accounts in the tenant's subtree (every organization for
// the root) with this period's billable spend, projection, available credit and latest statement. Requires
// iam:billing:read.
func (api *BillingAPI) Accounts(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingAccountsInput]) (Out[apitypes.BillingAccountsOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:read", "billing",
		func(ctx context.Context, call MutationContext) ([]any, error) {
			tx, realm := call.Tx, call.Tenant
			service := api.service()
			period, err := service.CurrentPeriod()
			if err != nil {
				return nil, err
			}
			now := server.Now()
			report, err := service.Report(ctx, tx, realm, core.NewObject("period", period, "groupBy", "tenant"), nil, nil)
			if err != nil {
				return nil, err
			}
			forecast, total := report.Get("forecast"), report.Get("total")
			hasFactor := false
			factor := 0.0
			if truthy(forecast) && jsNumber(member(total, "costMicros")) > 0 {
				hasFactor = true
				factor = jsNumber(member(forecast, "costMicros")) / jsNumber(member(total, "costMicros"))
			}
			order := []string{}
			accounts := map[string]*core.Object{}
			add := func(account *core.Object) {
				id := billingStr(account, "id")
				if _, ok := accounts[id]; !ok {
					order = append(order, id)
				}
				accounts[id] = account
			}
			top, err := AccountOf(ctx, server, tx, realm)
			if err != nil {
				return nil, err
			}
			inside, err := api.inSubtree(ctx, tx, realm, top.Get("id"))
			if err != nil {
				return nil, err
			}
			if inside {
				add(top)
			}
			tenants, err := Subtree(ctx, server, tx, realm)
			if err != nil {
				return nil, err
			}
			for _, tenant := range tenants {
				account, err := AccountOf(ctx, server, tx, tenant)
				if err != nil {
					return nil, err
				}
				if account.Get("parentId") == nil {
					continue
				}
				inside, err := api.inSubtree(ctx, tx, realm, account.Get("id"))
				if err != nil {
					return nil, err
				}
				if inside {
					add(account)
				}
			}
			result := []*core.Object{}
			for _, id := range order {
				account := accounts[id]
				if account.Get("parentId") == nil {
					continue
				}
				spend, err := AccountSpend(ctx, server, tx, account, period, nil)
				if err != nil {
					return nil, err
				}
				found, err := tx.Find(ctx, BillingCollections.Statements, core.NewObject("tenantId", account.Get("id")), nil)
				if err != nil {
					return nil, err
				}
				statements := []*core.Object{}
				for _, statement := range found {
					if statement.Get("status") != "draft" {
						statements = append(statements, statement)
					}
				}
				billingSort(statements, func(a, b *core.Object) float64 {
					first := -1.0
					if billingLess(a.Get("period"), b.Get("period")) {
						first = 1
					}
					return billingOr(first, billingNum(b, "issuedAt")-billingNum(a, "issuedAt"))
				})
				calc := &billingCalc{}
				due := 0.0
				for _, statement := range statements {
					due += calc.due(statement)
				}
				outstandingMicros := calc.round(due)
				creditRecords, err := tx.Find(ctx, BillingCollections.Credits, core.NewObject("tenantId", account.Get("id")), nil)
				if err != nil {
					return nil, err
				}
				credits := []*core.Object{}
				for _, credit := range creditRecords {
					view, err := billingCreditView(credit, now)
					if err != nil {
						return nil, err
					}
					if view.Get("active") == true {
						credits = append(credits, view)
					}
				}
				profile, err := ProfileOf(ctx, tx, billingStr(account, "id"))
				if err != nil {
					return nil, err
				}
				billable := spend.Get("billableMicros")
				overview := core.NewObject("accountId", account.Get("id"), "name", account.Get("name"), "hasProfile", profile != nil,
					"monthToDateMicros", billable, "monthToDate", calc.units(billable), "totalMicros", spend.Get("totalMicros"))
				if hasFactor {
					overview.Set("forecastMicros", calc.round(jsNumber(billable)*factor))
				}
				overview.Set("creditsMicros", calc.round(billingSum(credits, "remainingMicros"))).
					Set("outstandingMicros", outstandingMicros)
				if calc.err != nil {
					return nil, calc.err
				}
				if len(statements) > 0 {
					last, err := billingSummary(statements[0], now, account.Get("name"))
					if err != nil {
						return nil, err
					}
					overview.Set("lastStatement", last)
				}
				result = append(result, overview)
			}
			billingSort(result, func(a, b *core.Object) float64 {
				return billingOr(billingNum(b, "monthToDateMicros")-billingNum(a, "monthToDateMicros"), billingByName(a, b))
			})
			return billingList(result), nil
		}, false)
	return Out[apitypes.BillingAccountsOutput]{Value: result}, err
}

// Anomalies is POST {basePath}/billing/anomalies. Spend spikes in the tenant's subtree on `day` (default yesterday):
// people, teams and meters that spent at least `factor` (3) times their average over the `baselineDays` (14) before,
// and at least `minimum` (10 currency units) more, plus new spending above `minimum`. Largest increase first, at
// most 50. Requires iam:billing:read.
func (api *BillingAPI) Anomalies(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingAnomaliesInput]) (Out[apitypes.BillingAnomaliesOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:read", "billing",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			anomalies, err := api.service().Anomalies(ctx, call.Tx, call.Tenant, billingWithout(input.Body, "tenantId"))
			if err != nil {
				return nil, err
			}
			return core.NewObject("tenantId", call.Tenant.Get("id"), "anomalies", billingList(anomalies)), nil
		}, false)
	return Out[apitypes.BillingAnomaliesOutput]{Value: result}, err
}

// ExportSpend is POST {basePath}/billing/exportSpend. A spend report as CSV (the same query as `spend`): one row per
// group with the amount, share, events and a column per meter's quantity, then a total row. Requires
// iam:billing:read.
func (api *BillingAPI) ExportSpend(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingExportSpendInput]) (Out[apitypes.BillingExportSpendOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:read", "billing",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			realm := call.Tenant
			service := api.service()
			report, err := service.Report(ctx, call.Tx, realm, billingWithout(input.Body, "tenantId"), nil, nil)
			if err != nil {
				return nil, err
			}
			body, err := service.SpendCsv(report)
			if err != nil {
				return nil, err
			}
			filename := "spend-" + jsString(coalesce(realm.Get("slug"), realm.Get("id"))) + "-" + billingStr(report, "period") + "-" +
				strings.Replace(billingStr(report, "groupBy"), ":", "-", 1) + ".csv"
			return core.NewObject("filename", filename, "contentType", "text/csv; charset=utf-8", "body", body), nil
		}, false)
	return Out[apitypes.BillingExportSpendOutput]{Value: result}, err
}

// ExportStatement is POST {basePath}/billing/exportStatement. A statement as CSV: its lines, credit and total, then
// the breakdown by project, team, department and person.
func (api *BillingAPI) ExportStatement(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingExportStatementInput]) (Out[apitypes.BillingExportStatementOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:read", "billing/statements",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			statement, err := api.scopedStatement(ctx, call.Tx, call.Tenant, input.Get("statementId"))
			if err != nil {
				return nil, err
			}
			body, err := api.service().StatementCsv(statement)
			if err != nil {
				return nil, err
			}
			return core.NewObject("filename", billingStr(statement, "number")+".csv", "contentType", "text/csv; charset=utf-8", "body", body), nil
		}, false)
	return Out[apitypes.BillingExportStatementOutput]{Value: result}, err
}

// ---------------------------------------------------------------------------------------------------------------
// Budgets

// CreateBudget is POST {basePath}/billing/createBudget. Creates a spend budget owned by the tenant: an `amount`
// (currency units) per `month` (default), `quarter` or `year` for the tenant or one below it, a `team`, a
// `department` or an `identity`, optionally over some `meters`. Alerts fire at each of `thresholds` (default 50, 80,
// 100 percent) and, with `forecastAlerts` (default on), when the projection passes 100%. `enforce` makes
// `billing.check` and `record({ enforceBudgets })` refuse covered usage once the budget is spent. Names are unique
// per tenant; at most 200. Requires iam:billing:manage; audited as `billing:budget-create`.
func (api *BillingAPI) CreateBudget(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingCreateBudgetInput]) (Out[apitypes.BillingCreateBudgetOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/budgets",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := billingWritable(realm); err != nil {
				return nil, err
			}
			body, err := Object(input.Body)
			if err != nil {
				return nil, err
			}
			fields, err := budgetSettings(body, nil)
			if err != nil {
				return nil, err
			}
			subject, err := api.budgetSubject(ctx, tx, realm, input.Get("subjectType"), input.Get("subjectId"))
			if err != nil {
				return nil, err
			}
			existing, err := tx.Find(ctx, BillingCollections.Budgets, core.NewObject("tenantId", realm.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			if len(existing) >= maxBudgetsPerTenant {
				return nil, core.NewIamError("LIMIT_EXCEEDED", "A tenant can have at most "+jsString(float64(maxBudgetsPerTenant))+" budgets", 409)
			}
			uniqueKey := "name:" + core.JSLower(billingStr(fields, "name"))
			for _, budget := range existing {
				if budget.Get("uniqueKey") == uniqueKey {
					return nil, core.NewIamError("CONFLICT", "A budget with this name already exists", 409)
				}
			}
			now := server.Now()
			actor := principal.Identity.Get("id")
			record := core.NewObject("id", ID(), "tenantId", realm.Get("id"), "uniqueKey", uniqueKey)
			record.Assign(fields, subject)
			record.Set("createdAt", now).Set("createdBy", actor).Set("updatedAt", now).Set("updatedBy", actor)
			budget, err := tx.Insert(ctx, BillingCollections.Budgets, record)
			if err != nil {
				return nil, err
			}
			if err := api.audit(ctx, tx, principal, "billing:budget-create", realm.Get("id"), "billing/budgets/"+billingStr(budget, "id"), core.NewObject(
				"budgetId", budget.Get("id"), "name", budget.Get("name"), "subjectType", budget.Get("subjectType"),
				"subjectId", budget.Get("subjectId"), "amountMicros", budget.Get("amountMicros"), "period", budget.Get("period"),
				"enforce", budget.Get("enforce"),
			)); err != nil {
				return nil, err
			}
			return api.budgetView(ctx, tx, budget)
		}, false)
	return Out[apitypes.BillingCreateBudgetOutput]{Value: result}, err
}

// UpdateBudget is POST {basePath}/billing/updateBudget. Changes a budget's name, amount, period, meters (`null` for
// all), thresholds, alerts or enforcement; its subject stays. Requires iam:billing:manage; audited as
// `billing:budget-update`.
func (api *BillingAPI) UpdateBudget(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingUpdateBudgetInput]) (Out[apitypes.BillingUpdateBudgetOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/budgets",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := billingWritable(realm); err != nil {
				return nil, err
			}
			budget, err := api.ownBudget(ctx, tx, realm.Get("id"), input.Get("budgetId"))
			if err != nil {
				return nil, err
			}
			body, err := Object(input.Body)
			if err != nil {
				return nil, err
			}
			fields, err := budgetSettings(body, budget)
			if err != nil {
				return nil, err
			}
			uniqueKey := "name:" + core.JSLower(billingStr(fields, "name"))
			if uniqueKey != budget.Get("uniqueKey") {
				taken, err := tx.Find(ctx, BillingCollections.Budgets, core.NewObject("tenantId", realm.Get("id"), "uniqueKey", uniqueKey), nil)
				if err != nil {
					return nil, err
				}
				if len(taken) > 0 {
					return nil, core.NewIamError("CONFLICT", "A budget with this name already exists", 409)
				}
			}
			record := billingWithout(budget, "meters").Assign(fields)
			record.Set("uniqueKey", uniqueKey).Set("updatedAt", server.Now()).Set("updatedBy", principal.Identity.Get("id"))
			next, err := tx.Put(ctx, BillingCollections.Budgets, record)
			if err != nil {
				return nil, err
			}
			if err := api.audit(ctx, tx, principal, "billing:budget-update", realm.Get("id"), "billing/budgets/"+billingStr(budget, "id"), core.NewObject(
				"budgetId", budget.Get("id"), "name", next.Get("name"), "amountMicros", next.Get("amountMicros"),
				"period", next.Get("period"), "enforce", next.Get("enforce"),
			)); err != nil {
				return nil, err
			}
			return api.budgetView(ctx, tx, next)
		}, false)
	return Out[apitypes.BillingUpdateBudgetOutput]{Value: result}, err
}

// DeleteBudget is POST {basePath}/billing/deleteBudget. Deletes a budget and its alert history. Requires
// iam:billing:manage; audited as `billing:budget-delete`.
func (api *BillingAPI) DeleteBudget(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingDeleteBudgetInput]) (Out[apitypes.BillingDeleteBudgetOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/budgets",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			budget, err := api.ownBudget(ctx, tx, realm.Get("id"), input.Get("budgetId"))
			if err != nil {
				return nil, err
			}
			alerts, err := tx.Find(ctx, BillingCollections.BudgetAlerts, core.NewObject("tenantId", realm.Get("id"), "budgetId", budget.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			for _, alert := range alerts {
				if err := tx.Delete(ctx, BillingCollections.BudgetAlerts, billingStr(alert, "id")); err != nil {
					return nil, err
				}
			}
			if err := tx.Delete(ctx, BillingCollections.Budgets, billingStr(budget, "id")); err != nil {
				return nil, err
			}
			if err := api.audit(ctx, tx, principal, "billing:budget-delete", realm.Get("id"), "billing/budgets/"+billingStr(budget, "id"),
				core.NewObject("budgetId", budget.Get("id"), "name", budget.Get("name"))); err != nil {
				return nil, err
			}
			return core.NewObject("success", true), nil
		}, false)
	return Out[apitypes.BillingDeleteBudgetOutput]{Value: result}, err
}

// ListBudgets is POST {basePath}/billing/listBudgets. The tenant's budgets with their spend, projection and
// thresholds reached this window. Requires iam:billing:read.
func (api *BillingAPI) ListBudgets(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingListBudgetsInput]) (Out[apitypes.BillingListBudgetsOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:read", "billing/budgets",
		func(ctx context.Context, call MutationContext) ([]any, error) {
			budgets, err := call.Tx.Find(ctx, BillingCollections.Budgets, core.NewObject("tenantId", call.Tenant.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			billingSort(budgets, billingByName)
			views := []any{}
			for _, budget := range budgets {
				view, err := api.budgetView(ctx, call.Tx, budget)
				if err != nil {
					return nil, err
				}
				views = append(views, view)
			}
			return views, nil
		}, false)
	return Out[apitypes.BillingListBudgetsOutput]{Value: result}, err
}

// Check is POST {basePath}/billing/check. Whether the caller's own usage (of `meter`, when given) is within every
// enforced budget that covers it: tenant budgets up the tree, their own, their teams' and their department's. Any
// credential of the tenant; not audited.
func (api *BillingAPI) Check(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingCheckInput]) (Out[apitypes.BillingCheckOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.BillingCheckOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.BillingCheckOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		realm, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		chain, err := server.Ancestry(ctx, tx, realm)
		if err != nil {
			return nil, err
		}
		inChain := false
		for _, tenant := range chain {
			if tenant.Get("id") == principal.Identity.Get("tenantId") {
				inChain = true
				break
			}
		}
		if !inChain {
			return nil, core.NewIamError("ACCESS_DENIED", "Budgets are checked in the credential’s own tenant", 403)
		}
		query := core.NewObject("identityId", principal.Identity.Get("id"))
		if value := input.Get("meter"); !isUndefined(value) {
			query.Set("meter", value)
		}
		return api.service().Check(ctx, tx, realm, query)
	})
	return Out[apitypes.BillingCheckOutput]{Value: result}, err
}

// ---------------------------------------------------------------------------------------------------------------
// Credits

// billingIsAccount is whether the realm is a billing account below the root.
func (api *BillingAPI) billingIsAccount(ctx context.Context, tx core.IamStore, realm *core.Object) (bool, error) {
	if realm.Get("parentId") == nil {
		return false, nil
	}
	account, err := AccountOf(ctx, api.server, tx, realm)
	if err != nil {
		return false, err
	}
	return account.Get("id") == realm.Get("id"), nil
}

// GrantCredit is POST {basePath}/billing/grantCredit. Grants credit to a billing account (the tenant must be one):
// statements draw on it, earliest expiry first. Root administrators only; audited as `billing:credit-grant`.
func (api *BillingAPI) GrantCredit(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingGrantCreditInput]) (Out[apitypes.BillingGrantCreditOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/credits",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := billingWritable(realm); err != nil {
				return nil, err
			}
			account, err := api.billingIsAccount(ctx, tx, realm)
			if err != nil {
				return nil, err
			}
			if !account {
				return nil, invalidInput("Credit is granted to a billing account (an organization or a tenant with a billing profile)")
			}
			amount, err := AmountMicros(input.Get("amount"), "amount")
			if err != nil {
				return nil, err
			}
			if amount <= 0 {
				return nil, invalidInput("amount must be above 0")
			}
			reason, err := Text(input.Get("reason"), "reason", 256)
			if err != nil {
				return nil, err
			}
			record := core.NewObject("id", ID(), "tenantId", realm.Get("id"), "amountMicros", amount, "remainingMicros", amount,
				"reason", core.JSTrim(reason))
			if value := input.Get("expiresAt"); !isUndefined(value) {
				expiresAt, err := server.BindingExpiry(value)
				if err != nil {
					return nil, err
				}
				record.Set("expiresAt", expiresAt)
			}
			record.Set("grantedAt", server.Now()).Set("grantedBy", principal.Identity.Get("id"))
			credit, err := tx.Insert(ctx, BillingCollections.Credits, record)
			if err != nil {
				return nil, err
			}
			metadata := core.NewObject("creditId", credit.Get("id"), "amountMicros", amount, "reason", credit.Get("reason"))
			if value := credit.Get("expiresAt"); !isUndefined(value) {
				metadata.Set("expiresAt", value)
			}
			if err := api.audit(ctx, tx, principal, "billing:credit-grant", realm.Get("id"), "billing/credits/"+billingStr(credit, "id"), metadata); err != nil {
				return nil, err
			}
			return billingCreditView(credit, server.Now())
		}, true)
	return Out[apitypes.BillingGrantCreditOutput]{Value: result}, err
}

// RevokeCredit is POST {basePath}/billing/revokeCredit. Withdraws what is left of a credit. Root administrators
// only; audited as `billing:credit-revoke`.
func (api *BillingAPI) RevokeCredit(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingRevokeCreditInput]) (Out[apitypes.BillingRevokeCreditOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/credits",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			creditID, err := Text(input.Get("creditId"), "creditId")
			if err != nil {
				return nil, err
			}
			credit, err := server.Scoped(ctx, tx, BillingCollections.Credits, creditID, billingStr(realm, "id"))
			if err != nil {
				return nil, err
			}
			if !isUndefined(credit.Get("revokedAt")) {
				return nil, core.NewIamError("INVALID_TRANSITION", "The credit is already revoked", 409)
			}
			next, err := tx.Put(ctx, BillingCollections.Credits, credit.Spread(core.NewObject("remainingMicros", 0.0, "revokedAt", server.Now())))
			if err != nil {
				return nil, err
			}
			if err := api.audit(ctx, tx, principal, "billing:credit-revoke", realm.Get("id"), "billing/credits/"+billingStr(credit, "id"),
				core.NewObject("creditId", credit.Get("id"), "forfeitedMicros", credit.Get("remainingMicros"))); err != nil {
				return nil, err
			}
			return billingCreditView(next, server.Now())
		}, true)
	return Out[apitypes.BillingRevokeCreditOutput]{Value: result}, err
}

// ListCredits is POST {basePath}/billing/listCredits. The credits of the tenant's billing account with the
// available balance; empty (with `inherited: true`) when an ancestor pays for the tenant. Requires iam:billing:read.
func (api *BillingAPI) ListCredits(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingListCreditsInput]) (Out[apitypes.BillingListCreditsOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:read", "billing/credits",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm := call.Tx, call.Tenant
			account, err := AccountOf(ctx, server, tx, realm)
			if err != nil {
				return nil, err
			}
			now := server.Now()
			if account.Get("id") != realm.Get("id") {
				return core.NewObject("accountId", account.Get("id"), "inherited", true, "balanceMicros", 0.0, "balance", 0.0, "credits", []any{}), nil
			}
			records, err := tx.Find(ctx, BillingCollections.Credits, core.NewObject("tenantId", realm.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			credits := make([]*core.Object, 0, len(records))
			for _, record := range records {
				view, err := billingCreditView(record, now)
				if err != nil {
					return nil, err
				}
				credits = append(credits, view)
			}
			billingSort(credits, func(a, b *core.Object) float64 {
				return billingOr(billingNum(b, "grantedAt")-billingNum(a, "grantedAt"), billingBefore(a.Get("id"), b.Get("id")))
			})
			active := []*core.Object{}
			for _, credit := range credits {
				if credit.Get("active") == true {
					active = append(active, credit)
				}
			}
			calc := &billingCalc{}
			balance := calc.round(billingSum(active, "remainingMicros"))
			out := core.NewObject("accountId", account.Get("id"), "inherited", false, "balanceMicros", balance,
				"balance", calc.units(balance), "credits", billingList(credits))
			return out, calc.err
		}, false)
	return Out[apitypes.BillingListCreditsOutput]{Value: result}, err
}

// ---------------------------------------------------------------------------------------------------------------
// Terms

// billingPercent is a contract percentage: null clears it, undefined keeps current, else 0-100 to three decimals.
func billingPercent(value any, current any, name string) (any, error) {
	if value == nil {
		return core.Undefined, nil
	}
	if isUndefined(value) {
		return current, nil
	}
	number, ok := core.Normalize(value).(float64)
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) || number < 0 || number > 100 {
		return nil, invalidInput(name + " must be a percentage from 0 to 100")
	}
	return billingMathRound(number*1000) / 1000, nil
}

// SetTerms is POST {basePath}/billing/setTerms. Sets a billing account's contract terms: `discountPercent` off usage,
// a `minimumCommitment` per month (currency units; a shortfall is billed as a true-up), and the `taxRatePercent`
// statements add, labelled `taxLabel`; `null` clears a term. Terms apply to statements issued from then on. Root
// administrators only; audited as `billing:terms`.
func (api *BillingAPI) SetTerms(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingSetTermsInput]) (Out[apitypes.BillingSetTermsOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/terms",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := billingWritable(realm); err != nil {
				return nil, err
			}
			account, err := api.billingIsAccount(ctx, tx, realm)
			if err != nil {
				return nil, err
			}
			if !account {
				return nil, invalidInput("Terms belong to a billing account (an organization or a tenant with a billing profile)")
			}
			existing, err := TermsOf(ctx, tx, billingStr(realm, "id"))
			if err != nil {
				return nil, err
			}
			discountPercent, err := billingPercent(input.Get("discountPercent"), existing.Get("discountPercent"), "discountPercent")
			if err != nil {
				return nil, err
			}
			taxRatePercent, err := billingPercent(input.Get("taxRatePercent"), existing.Get("taxRatePercent"), "taxRatePercent")
			if err != nil {
				return nil, err
			}
			var minimumCommitmentMicros any = core.Undefined
			switch value := input.Get("minimumCommitment"); {
			case value == nil:
			case isUndefined(value):
				minimumCommitmentMicros = existing.Get("minimumCommitmentMicros")
			default:
				micros, err := AmountMicros(value, "minimumCommitment")
				if err != nil {
					return nil, err
				}
				minimumCommitmentMicros = micros
			}
			var taxLabel any = core.Undefined
			switch value := input.Get("taxLabel"); {
			case value == nil:
			case isUndefined(value):
				taxLabel = existing.Get("taxLabel")
			default:
				label, err := Text(value, "taxLabel", 32)
				if err != nil {
					return nil, err
				}
				taxLabel = core.JSTrim(label)
			}
			var id any = ID()
			if existing != nil {
				id = existing.Get("id")
			}
			terms := core.NewObject("id", id, "tenantId", realm.Get("id"), "uniqueKey", "terms")
			if !isUndefined(discountPercent) {
				terms.Set("discountPercent", discountPercent)
			}
			if !isUndefined(minimumCommitmentMicros) {
				terms.Set("minimumCommitmentMicros", minimumCommitmentMicros)
			}
			if !isUndefined(taxRatePercent) {
				terms.Set("taxRatePercent", taxRatePercent)
			}
			if !isUndefined(taxLabel) {
				terms.Set("taxLabel", taxLabel)
			}
			terms.Set("setAt", server.Now()).Set("setBy", principal.Identity.Get("id"))
			if existing != nil {
				_, err = tx.Put(ctx, BillingCollections.Terms, terms)
			} else {
				_, err = tx.Insert(ctx, BillingCollections.Terms, terms)
			}
			if err != nil {
				return nil, err
			}
			if err := api.audit(ctx, tx, principal, "billing:terms", realm.Get("id"), "billing/terms", core.NewObject(
				"discountPercent", coalesce(terms.Get("discountPercent"), nil),
				"minimumCommitmentMicros", coalesce(terms.Get("minimumCommitmentMicros"), nil),
				"taxRatePercent", coalesce(terms.Get("taxRatePercent"), nil),
			)); err != nil {
				return nil, err
			}
			return billingTermsView(billingStr(realm, "id"), terms, true)
		}, true)
	return Out[apitypes.BillingSetTermsOutput]{Value: result}, err
}

// GetTerms is POST {basePath}/billing/getTerms. The contract terms of the tenant's billing account (empty when none
// are set; `inherited` when an ancestor pays for the tenant). Requires iam:billing:read.
func (api *BillingAPI) GetTerms(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingGetTermsInput]) (Out[apitypes.BillingGetTermsOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:read", "billing/terms",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			account, err := AccountOf(ctx, server, tx, realm)
			if err != nil {
				return nil, err
			}
			if account.Get("id") != realm.Get("id") {
				return core.NewObject("accountId", account.Get("id"), "inherited", true), nil
			}
			chain, err := server.Ancestry(ctx, tx, realm)
			if err != nil {
				return nil, err
			}
			terms, err := TermsOf(ctx, tx, billingStr(realm, "id"))
			if err != nil {
				return nil, err
			}
			return billingTermsView(billingStr(realm, "id"), terms, principal.Identity.Get("tenantId") == billingRootID(chain))
		}, false)
	return Out[apitypes.BillingGetTermsOutput]{Value: result}, err
}

// ---------------------------------------------------------------------------------------------------------------
// Profiles

// GetProfile is POST {basePath}/billing/getProfile. The billing profile of the tenant (or of `targetTenantId`, a
// tenant below it) and the account that pays for it. Requires iam:billing:read.
func (api *BillingAPI) GetProfile(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingGetProfileInput]) (Out[apitypes.BillingGetProfileOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:read", "billing/profile",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			target, err := api.profileTarget(ctx, call.Tx, call.Tenant, input.Get("targetTenantId"))
			if err != nil {
				return nil, err
			}
			profile, err := ProfileOf(ctx, call.Tx, billingStr(target, "id"))
			if err != nil {
				return nil, err
			}
			return api.profileView(ctx, call.Tx, target, profile)
		}, false)
	return Out[apitypes.BillingGetProfileOutput]{Value: result}, err
}

// SetProfile is POST {basePath}/billing/setProfile. Creates or updates a billing profile: company name, billing
// emails (statements go there), tax ID, address, purchase order, cost center, payment terms (days; beyond
// `billing.paymentTermsDays` only root administrators extend them); `null` clears a field. A profile below an
// organization makes that tenant its own billing account, which is the parent's decision: it is created from an
// ancestor (with `targetTenantId`). Requires iam:billing:manage; audited as `billing:profile`.
func (api *BillingAPI) SetProfile(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingSetProfileInput]) (Out[apitypes.BillingSetProfileOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/profile",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			target, err := api.profileTarget(ctx, tx, realm, input.Get("targetTenantId"))
			if err != nil {
				return nil, err
			}
			if err := billingWritable(target); err != nil {
				return nil, err
			}
			if target.Get("parentId") == nil {
				return nil, invalidInput("The platform tenant is not billed")
			}
			existing, err := ProfileOf(ctx, tx, billingStr(target, "id"))
			if err != nil {
				return nil, err
			}
			if existing == nil && target.Get("id") == realm.Get("id") {
				chain, err := server.Ancestry(ctx, tx, target)
				if err != nil {
					return nil, err
				}
				if len(chain) > 2 {
					return nil, NewOperationDenied("A tenant below an organization becomes its own billing account only from its parent (setProfile with targetTenantId)")
				}
			}
			optional := func(value any, current any, name string, max int) (any, error) {
				if value == nil {
					return core.Undefined, nil
				}
				if isUndefined(value) {
					return current, nil
				}
				text, err := Text(value, name, max)
				if err != nil {
					return nil, err
				}
				return core.JSTrim(text), nil
			}
			var billingEmails any
			if value := input.Get("billingEmails"); isUndefined(value) {
				billingEmails = coalesce(existing.Get("billingEmails"), []any{})
			} else {
				list, ok := value.([]any)
				if !ok || len(list) > 10 {
					return nil, invalidInput("billingEmails must list at most 10 addresses")
				}
				addresses := make([]string, len(list))
				for index, item := range list {
					address, err := Email(item)
					if err != nil {
						return nil, err
					}
					addresses[index] = address
				}
				billingEmails = stringsOf(unique(addresses))
			}
			var paymentTermsDays any = core.Undefined
			switch value := input.Get("paymentTermsDays"); {
			case value == nil:
			case isUndefined(value):
				paymentTermsDays = existing.Get("paymentTermsDays")
			default:
				days, err := Integer(value, "paymentTermsDays", 0, 365)
				if err != nil {
					return nil, err
				}
				paymentTermsDays = days
			}
			// Longer payment terms are credit the platform extends: billing managers keep the terms they have or
			// choose terms up to the deployment's default (`billing.paymentTermsDays`); only root administrators
			// grant more.
			defaultDays := api.settings().Get("paymentTermsDays")
			if !isUndefined(paymentTermsDays) && !strictEquals(paymentTermsDays, existing.Get("paymentTermsDays")) &&
				jsNumber(paymentTermsDays) > jsNumber(defaultDays) {
				root, err := server.RootPrincipal(ctx, tx, principal)
				if err != nil {
					return nil, err
				}
				if !root {
					return nil, NewOperationDenied("Payment terms above " + jsString(defaultDays) + " days are set by root administrators")
				}
			}
			fields := core.NewObject()
			for _, field := range []struct {
				name string
				max  int
			}{{"companyName", 256}, {"taxId", 64}, {"address", 1024}, {"purchaseOrder", 128}, {"costCenter", 128}} {
				value, err := optional(input.Get(field.name), existing.Get(field.name), field.name, field.max)
				if err != nil {
					return nil, err
				}
				if !isUndefined(value) {
					fields.Set(field.name, value)
				}
			}
			now := server.Now()
			actor := principal.Identity.Get("id")
			var id any = ID()
			if existing != nil {
				id = existing.Get("id")
			}
			profile := core.NewObject("id", id, "tenantId", target.Get("id"), "uniqueKey", "profile", "billingEmails", billingEmails)
			profile.Assign(fields)
			if !isUndefined(paymentTermsDays) {
				profile.Set("paymentTermsDays", paymentTermsDays)
			}
			profile.Set("createdAt", coalesce(existing.Get("createdAt"), now)).
				Set("createdBy", coalesce(existing.Get("createdBy"), actor)).
				Set("updatedAt", now).
				Set("updatedBy", actor)
			if existing != nil {
				_, err = tx.Put(ctx, BillingCollections.Profiles, profile)
			} else {
				_, err = tx.Insert(ctx, BillingCollections.Profiles, profile)
			}
			if err != nil {
				return nil, err
			}
			emailCount := 0
			if list, ok := billingEmails.([]any); ok {
				emailCount = len(list)
			}
			metadata := core.NewObject("targetTenantId", target.Get("id"), "created", existing == nil, "billingEmails", float64(emailCount))
			if value := profile.Get("companyName"); truthy(value) {
				metadata.Set("companyName", value)
			}
			if err := api.audit(ctx, tx, principal, "billing:profile", realm.Get("id"), "billing/profile/"+billingStr(target, "id"), metadata); err != nil {
				return nil, err
			}
			return api.profileView(ctx, tx, target, profile)
		}, false)
	return Out[apitypes.BillingSetProfileOutput]{Value: result}, err
}

// DeleteProfile is POST {basePath}/billing/deleteProfile. Removes a billing profile (the tenant's own, or
// `targetTenantId`'s below it). A tenant below an organization then rolls into its parent's account again, which
// only an ancestor may decide (call it from there). Requires iam:billing:manage; audited as `billing:profile-delete`.
func (api *BillingAPI) DeleteProfile(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingDeleteProfileInput]) (Out[apitypes.BillingDeleteProfileOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/profile",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			target, err := api.profileTarget(ctx, tx, realm, input.Get("targetTenantId"))
			if err != nil {
				return nil, err
			}
			existing, err := ProfileOf(ctx, tx, billingStr(target, "id"))
			if err != nil {
				return nil, err
			}
			if existing == nil {
				return nil, core.NewIamError("NOT_FOUND", "This tenant has no billing profile", 404)
			}
			if target.Get("id") == realm.Get("id") {
				chain, err := server.Ancestry(ctx, tx, target)
				if err != nil {
					return nil, err
				}
				if len(chain) > 2 {
					return nil, NewOperationDenied("Folding a tenant back into its parent’s billing account is decided from the parent (targetTenantId)")
				}
			}
			if err := tx.Delete(ctx, BillingCollections.Profiles, billingStr(existing, "id")); err != nil {
				return nil, err
			}
			if err := api.audit(ctx, tx, principal, "billing:profile-delete", realm.Get("id"), "billing/profile/"+billingStr(target, "id"),
				core.NewObject("targetTenantId", target.Get("id"))); err != nil {
				return nil, err
			}
			return core.NewObject("success", true), nil
		}, false)
	return Out[apitypes.BillingDeleteProfileOutput]{Value: result}, err
}

// ---------------------------------------------------------------------------------------------------------------
// Statements

// ListStatements is POST {basePath}/billing/listStatements. Statements of the billing accounts in the tenant's
// subtree (all for the root), newest period first, optionally by `status` or `period`. Requires iam:billing:read.
func (api *BillingAPI) ListStatements(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingListStatementsInput]) (Out[apitypes.BillingListStatementsOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:read", "billing/statements",
		func(ctx context.Context, call MutationContext) ([]any, error) {
			tx, realm := call.Tx, call.Tenant
			var period any = core.Undefined
			if value := input.Get("period"); !isUndefined(value) {
				text, err := BillingPeriod(value, "period")
				if err != nil {
					return nil, err
				}
				period = text
			}
			now := server.Now()
			names := map[string]any{}
			statements, err := api.scopeStatements(ctx, tx, realm)
			if err != nil {
				return nil, err
			}
			status := input.Get("status")
			result := []*core.Object{}
			for _, statement := range statements {
				if !isUndefined(status) && !strictEquals(statement.Get("status"), status) {
					continue
				}
				if !isUndefined(period) && !strictEquals(statement.Get("period"), period) {
					continue
				}
				tenantID := billingStr(statement, "tenantId")
				if _, ok := names[tenantID]; !ok {
					name, err := billingTenantName(ctx, tx, statement.Get("tenantId"))
					if err != nil {
						return nil, err
					}
					names[tenantID] = name
				}
				view, err := billingSummary(statement, now, names[tenantID])
				if err != nil {
					return nil, err
				}
				result = append(result, view)
			}
			billingSort(result, billingNewestPeriod)
			return billingList(result), nil
		}, false)
	return Out[apitypes.BillingListStatementsOutput]{Value: result}, err
}

// billingNewestPeriod is `(a.period < b.period ? 1 : a.period > b.period ? -1 : 0) || b.issuedAt - a.issuedAt`.
func billingNewestPeriod(a, b *core.Object) float64 {
	first := 0.0
	if billingLess(a.Get("period"), b.Get("period")) {
		first = 1
	} else if billingLess(b.Get("period"), a.Get("period")) {
		first = -1
	}
	return billingOr(first, billingNum(b, "issuedAt")-billingNum(a, "issuedAt"))
}

// GetStatement is POST {basePath}/billing/getStatement. A statement with its lines, credits, allocation breakdown and
// bill-to details; `verified` re-checks its content hash. Requires iam:billing:read.
func (api *BillingAPI) GetStatement(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingGetStatementInput]) (Out[apitypes.BillingGetStatementOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:read", "billing/statements",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			statement, err := api.scopedStatement(ctx, call.Tx, call.Tenant, input.Get("statementId"))
			if err != nil {
				return nil, err
			}
			total, err := UnitsOf(billingNum(statement, "totalMicros"))
			if err != nil {
				return nil, err
			}
			view, err := billingSummary(statement, server.Now(), core.Undefined)
			if err != nil {
				return nil, err
			}
			hash, err := StatementHash(statement)
			if err != nil {
				return nil, err
			}
			return statement.Spread().
				Set("total", total).
				Set("overdue", view.Get("overdue")).
				Set("verified", statement.Get("hash") == hash), nil
		}, false)
	return Out[apitypes.BillingGetStatementOutput]{Value: result}, err
}

// PreviewStatement is POST {basePath}/billing/previewStatement. What the tenant's statement for a period (default
// the current one, so far) would hold, without issuing it. The tenant must be its own billing account or above it.
// Requires iam:billing:read.
func (api *BillingAPI) PreviewStatement(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingPreviewStatementInput]) (Out[apitypes.BillingPreviewStatementOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:read", "billing/statements",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm := call.Tx, call.Tenant
			period, err := api.periodOrCurrent(input.Get("period"))
			if err != nil {
				return nil, err
			}
			account, err := AccountOf(ctx, server, tx, realm)
			if err != nil {
				return nil, err
			}
			if account.Get("id") != realm.Get("id") || realm.Get("parentId") == nil {
				return nil, invalidInput("Only a billing account (an organization or a tenant with a profile) has statements")
			}
			return api.service().DraftStatement(ctx, tx, account, period, nil, nil)
		}, false)
	return Out[apitypes.BillingPreviewStatementOutput]{Value: result}, err
}

// ClosePeriod is POST {basePath}/billing/closePeriod. Issues statements for a past period (default the previous one)
// for every billing account, or only `accountId`'s. With `draft` they are kept as drafts to review and finalize
// (`finalizeInvoice`); the default follows `billing.autoFinalize`. Called on the root tenant; root administrators
// only (the operation is audited as `iam:billing:manage`, each statement as `billing:statement`).
func (api *BillingAPI) ClosePeriod(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingClosePeriodInput]) (Out[apitypes.BillingClosePeriodOutput], error) {
	server := api.server
	_, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/periods",
		func(ctx context.Context, call MutationContext) (any, error) {
			if call.Tenant.Get("parentId") != nil {
				return nil, invalidInput("Periods are closed on the platform (root) tenant")
			}
			return nil, nil
		}, true)
	if err != nil {
		return Out[apitypes.BillingClosePeriodOutput]{}, err
	}
	options := core.NewObject()
	if value := input.Get("period"); !isUndefined(value) {
		options.Set("period", value)
	}
	if value := input.Get("accountId"); !isUndefined(value) {
		options.Set("tenantId", value)
	}
	if value := input.Get("draft"); !isUndefined(value) {
		options.Set("draft", value)
	}
	result, err := api.service().ClosePeriod(ctx, options)
	return Out[apitypes.BillingClosePeriodOutput]{Value: result}, err
}

// MarkPaid is POST {basePath}/billing/markPaid. Marks a finalized (or uncollectible) statement paid: records a
// `manual` payment of the amount still due, with an optional `reference`. Root administrators only; audited as
// `billing:statement-paid`.
func (api *BillingAPI) MarkPaid(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingMarkPaidInput]) (Out[apitypes.BillingMarkPaidOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/statements",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			statement, err := api.accountStatement(ctx, tx, realm, input.Get("statementId"))
			if err != nil {
				return nil, err
			}
			payment := core.NewObject()
			if value := input.Get("reference"); !isUndefined(value) {
				payment.Set("reference", value)
			}
			recorded, err := api.service().RecordPayment(ctx, tx, statement, payment, billingStr(principal.Identity, "id"))
			if err != nil {
				return nil, err
			}
			next, _ := recorded.Get("statement").(*core.Object)
			metadata := core.NewObject("number", statement.Get("number"), "totalMicros", statement.Get("totalMicros"))
			if value := next.Get("paymentReference"); truthy(value) {
				metadata.Set("reference", value)
			}
			if err := api.audit(ctx, tx, principal, "billing:statement-paid", statement.Get("tenantId"), "billing/statements/"+billingStr(statement, "id"), metadata); err != nil {
				return nil, err
			}
			return api.summaryOf(ctx, tx, next)
		}, true)
	return Out[apitypes.BillingMarkPaidOutput]{Value: result}, err
}

// VoidStatement is POST {basePath}/billing/voidStatement. Voids a statement: its credits are restored and its period
// reopens for the account (fix usage, then close the period again for a new statement). Root administrators only;
// audited as `billing:statement-void`.
func (api *BillingAPI) VoidStatement(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingVoidStatementInput]) (Out[apitypes.BillingVoidStatementOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/statements",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			statement, err := api.accountStatement(ctx, tx, realm, input.Get("statementId"))
			if err != nil {
				return nil, err
			}
			text, err := Text(input.Get("reason"), "reason", 512)
			if err != nil {
				return nil, err
			}
			reason := core.JSTrim(text)
			next, err := api.service().VoidStatement(ctx, tx, statement, principal, reason)
			if err != nil {
				return nil, err
			}
			if err := api.audit(ctx, tx, principal, "billing:statement-void", statement.Get("tenantId"), "billing/statements/"+billingStr(statement, "id"),
				core.NewObject("number", statement.Get("number"), "reason", reason, "restoredCreditMicros", statement.Get("creditsMicros"))); err != nil {
				return nil, err
			}
			return api.summaryOf(ctx, tx, next)
		}, true)
	return Out[apitypes.BillingVoidStatementOutput]{Value: result}, err
}

// ---------------------------------------------------------------------------------------------------------------
// Invoicing

// FinalizeInvoice is POST {basePath}/billing/finalizeInvoice. Finalizes a draft invoice (kept as a draft by
// `closePeriod({ draft: true })` or `billing.autoFinalize: false`): it is recomputed with the latest usage and
// invoice items, numbered, and sent. Root administrators only; audited as `billing:statement-finalize` (and
// `billing:statement`).
func (api *BillingAPI) FinalizeInvoice(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingFinalizeInvoiceInput]) (Out[apitypes.BillingFinalizeInvoiceOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/statements",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			statement, err := api.accountStatement(ctx, tx, realm, input.Get("statementId"))
			if err != nil {
				return nil, err
			}
			finalized, err := api.service().FinalizeDraft(ctx, tx, statement, billingStr(principal.Identity, "id"))
			if err != nil {
				return nil, err
			}
			next, _ := finalized.Get("statement").(*core.Object)
			if err := api.audit(ctx, tx, principal, "billing:statement-finalize", statement.Get("tenantId"), "billing/statements/"+billingStr(next, "id"),
				core.NewObject("number", next.Get("number"), "period", next.Get("period"), "totalMicros", next.Get("totalMicros"),
					"recipients", finalized.Get("recipients"))); err != nil {
				return nil, err
			}
			return api.summaryOf(ctx, tx, next)
		}, true)
	return Out[apitypes.BillingFinalizeInvoiceOutput]{Value: result}, err
}

// RecordPayment is POST {basePath}/billing/recordPayment. Records a payment against a finalized or uncollectible
// invoice: `amount` (currency units, default the amount due), `method` (`card`, `bank_transfer`, `check`, ...;
// default `manual`), `reference`, and `receivedAt`. Partial payments leave the rest due; once covered the invoice is
// paid; an overpayment becomes account credit. Root administrators only; audited as `billing:payment`.
func (api *BillingAPI) RecordPayment(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingRecordPaymentInput]) (Out[apitypes.BillingRecordPaymentOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/statements",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			statement, err := api.accountStatement(ctx, tx, realm, input.Get("statementId"))
			if err != nil {
				return nil, err
			}
			recorded, err := api.service().RecordPayment(ctx, tx, statement, input.Body, billingStr(principal.Identity, "id"))
			if err != nil {
				return nil, err
			}
			next, _ := recorded.Get("statement").(*core.Object)
			payment, _ := recorded.Get("payment").(*core.Object)
			metadata := core.NewObject("number", next.Get("number"), "amountMicros", payment.Get("amountMicros"), "method", payment.Get("method"))
			if value := payment.Get("reference"); truthy(value) {
				metadata.Set("reference", value)
			}
			if value := payment.Get("overpaymentMicros"); truthy(value) {
				metadata.Set("overpaymentMicros", value)
			}
			metadata.Set("status", next.Get("status"))
			if err := api.audit(ctx, tx, principal, "billing:payment", statement.Get("tenantId"), "billing/statements/"+billingStr(next, "id"), metadata); err != nil {
				return nil, err
			}
			summary, err := api.summaryOf(ctx, tx, next)
			if err != nil {
				return nil, err
			}
			return core.NewObject("statement", summary, "payment", recorded.Get("payment")), nil
		}, true)
	return Out[apitypes.BillingRecordPaymentOutput]{Value: result}, err
}

// MarkUncollectible is POST {basePath}/billing/markUncollectible. Writes a finalized invoice off as uncollectible (a
// later payment still settles it). Root administrators only; audited as `billing:statement-uncollectible`.
func (api *BillingAPI) MarkUncollectible(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingMarkUncollectibleInput]) (Out[apitypes.BillingMarkUncollectibleOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/statements",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			statement, err := api.accountStatement(ctx, tx, realm, input.Get("statementId"))
			if err != nil {
				return nil, err
			}
			next, err := api.service().MarkUncollectible(ctx, tx, statement)
			if err != nil {
				return nil, err
			}
			due, err := AmountDue(next)
			if err != nil {
				return nil, err
			}
			if err := api.audit(ctx, tx, principal, "billing:statement-uncollectible", statement.Get("tenantId"), "billing/statements/"+billingStr(next, "id"),
				core.NewObject("number", next.Get("number"), "amountDueMicros", due)); err != nil {
				return nil, err
			}
			return api.summaryOf(ctx, tx, next)
		}, true)
	return Out[apitypes.BillingMarkUncollectibleOutput]{Value: result}, err
}

// CreateCreditNote is POST {basePath}/billing/createCreditNote. Issues a credit note against an invoice for `amount`
// (currency units, default everything not yet credited) with a `reason` (`duplicate`, `fraudulent`, `order_change`,
// `product_unsatisfactory`, `other`) and `memo`. It reduces the amount due first; a part already paid becomes account
// credit, or with `refund: true` is recorded as refunded outside Better IAM. Root administrators only; audited as
// `billing:credit-note`.
func (api *BillingAPI) CreateCreditNote(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingCreateCreditNoteInput]) (Out[apitypes.BillingCreateCreditNoteOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/statements",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			statement, err := api.accountStatement(ctx, tx, realm, input.Get("statementId"))
			if err != nil {
				return nil, err
			}
			created, err := api.service().CreateCreditNote(ctx, tx, statement, input.Body, billingStr(principal.Identity, "id"))
			if err != nil {
				return nil, err
			}
			next, _ := created.Get("statement").(*core.Object)
			creditNote, _ := created.Get("creditNote").(*core.Object)
			applied := creditNote.Get("applied")
			if err := api.audit(ctx, tx, principal, "billing:credit-note", statement.Get("tenantId"), "billing/statements/"+billingStr(next, "id"), core.NewObject(
				"number", creditNote.Get("number"), "statementNumber", next.Get("number"), "amountMicros", creditNote.Get("amountMicros"),
				"reason", creditNote.Get("reason"), "dueMicros", member(applied, "dueMicros"), "creditMicros", member(applied, "creditMicros"),
				"refundMicros", member(applied, "refundMicros"),
			)); err != nil {
				return nil, err
			}
			summary, err := api.summaryOf(ctx, tx, next)
			if err != nil {
				return nil, err
			}
			view, err := billingCreditNoteView(creditNote)
			if err != nil {
				return nil, err
			}
			return core.NewObject("statement", summary, "creditNote", view), nil
		}, true)
	return Out[apitypes.BillingCreateCreditNoteOutput]{Value: result}, err
}

// ListCreditNotes is POST {basePath}/billing/listCreditNotes. Credit notes of the billing accounts in the tenant's
// subtree, or of one `statementId`. Requires iam:billing:read.
func (api *BillingAPI) ListCreditNotes(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingListCreditNotesInput]) (Out[apitypes.BillingListCreditNotesOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:read", "billing/statements",
		func(ctx context.Context, call MutationContext) ([]any, error) {
			tx, realm := call.Tx, call.Tenant
			var notes []*core.Object
			if value := input.Get("statementId"); !isUndefined(value) {
				statement, err := api.scopedStatement(ctx, tx, realm, value)
				if err != nil {
					return nil, err
				}
				if notes, err = tx.Find(ctx, BillingCollections.CreditNotes, core.NewObject("tenantId", statement.Get("tenantId"), "statementId", statement.Get("id")), nil); err != nil {
					return nil, err
				}
			} else {
				covered, err := api.coveredAccounts(ctx, tx, realm)
				if err != nil {
					return nil, err
				}
				all, err := tx.Find(ctx, BillingCollections.CreditNotes, nil, nil)
				if err != nil {
					return nil, err
				}
				for _, note := range all {
					if billingCovers(covered, note.Get("tenantId")) {
						notes = append(notes, note)
					}
				}
			}
			billingSort(notes, func(a, b *core.Object) float64 {
				second := -1.0
				if billingLess(a.Get("number"), b.Get("number")) {
					second = 1
				}
				return billingOr(billingNum(b, "issuedAt")-billingNum(a, "issuedAt"), second)
			})
			views := []any{}
			for _, note := range notes {
				view, err := billingCreditNoteView(note)
				if err != nil {
					return nil, err
				}
				views = append(views, view)
			}
			return views, nil
		}, false)
	return Out[apitypes.BillingListCreditNotesOutput]{Value: result}, err
}

// RenderInvoice is POST {basePath}/billing/renderInvoice. An invoice as a standalone HTML page to print or save as
// PDF: the issuer (`billing.issuer`), bill-to details, lines with tier sub-lines and service periods, discounts,
// credit, tax, payments, credit notes and amount due. Requires iam:billing:read.
func (api *BillingAPI) RenderInvoice(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingRenderInvoiceInput]) (Out[apitypes.BillingRenderInvoiceOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:read", "billing/statements",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm := call.Tx, call.Tenant
			statement, err := api.scopedStatement(ctx, tx, realm, input.Get("statementId"))
			if err != nil {
				return nil, err
			}
			creditNotes, err := tx.Find(ctx, BillingCollections.CreditNotes, core.NewObject("tenantId", statement.Get("tenantId"), "statementId", statement.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			name := statement.Get("number")
			if !truthy(name) {
				name = "draft-" + billingStr(statement, "period")
			}
			options := core.NewObject()
			if issuer := api.settings().Get("issuer"); truthy(issuer) {
				options.Set("issuer", issuer)
			}
			billingSort(creditNotes, func(a, b *core.Object) float64 { return billingBefore(a.Get("number"), b.Get("number")) })
			options.Set("creditNotes", billingList(creditNotes))
			body, err := RenderInvoiceHtml(statement, options)
			if err != nil {
				return nil, err
			}
			return core.NewObject("filename", jsString(name)+".html", "contentType", "text/html; charset=utf-8", "body", body), nil
		}, false)
	return Out[apitypes.BillingRenderInvoiceOutput]{Value: result}, err
}

// ListInvoiceItems is POST {basePath}/billing/listInvoiceItems. Pending (and invoiced) invoice items of the billing
// accounts in the tenant's subtree, newest first, optionally by `status`. Requires iam:billing:read.
func (api *BillingAPI) ListInvoiceItems(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingListInvoiceItemsInput]) (Out[apitypes.BillingListInvoiceItemsOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:read", "billing/invoice-items",
		func(ctx context.Context, call MutationContext) ([]any, error) {
			tx, realm := call.Tx, call.Tenant
			status := input.Get("status")
			if !isUndefined(status) && status != "pending" && status != "invoiced" {
				return nil, invalidInput("status must be 'pending' or 'invoiced'")
			}
			covered, err := api.coveredAccounts(ctx, tx, realm)
			if err != nil {
				return nil, err
			}
			filter := core.NewObject()
			if truthy(status) {
				filter.Set("status", status)
			}
			items, err := tx.Find(ctx, BillingCollections.InvoiceItems, filter, nil)
			if err != nil {
				return nil, err
			}
			matching := []*core.Object{}
			for _, item := range items {
				if billingCovers(covered, item.Get("tenantId")) {
					matching = append(matching, item)
				}
			}
			billingSort(matching, func(a, b *core.Object) float64 {
				second := -1.0
				if billingLess(a.Get("id"), b.Get("id")) {
					second = 1
				}
				return billingOr(billingNum(b, "createdAt")-billingNum(a, "createdAt"), second)
			})
			return billingInvoiceItemViews(matching)
		}, false)
	return Out[apitypes.BillingListInvoiceItemsOutput]{Value: result}, err
}

// CreateInvoiceItem is POST {basePath}/billing/createInvoiceItem. Adds a one-off charge (or, with a negative
// `amount`, a credit) to the billing account's next invoice, or to the invoice for `period`: `description`, `amount`
// per unit in currency units, `quantity` (default 1), `metadata`. Root administrators only; audited as
// `billing:invoice-item`.
func (api *BillingAPI) CreateInvoiceItem(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingCreateInvoiceItemInput]) (Out[apitypes.BillingCreateInvoiceItemOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/invoice-items",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := billingWritable(realm); err != nil {
				return nil, err
			}
			account, err := api.ownAccount(ctx, tx, realm)
			if err != nil {
				return nil, err
			}
			body, err := Object(input.Body)
			if err != nil {
				return nil, err
			}
			fields, err := InvoiceItemInput(body)
			if err != nil {
				return nil, err
			}
			if period := fields.Get("period"); truthy(period) {
				invoiced, err := api.service().StatementFor(ctx, tx, billingStr(account, "id"), jsString(period))
				if err != nil {
					return nil, err
				}
				if invoiced != nil && invoiced.Get("status") != "draft" {
					return nil, core.NewIamError("BILLING_PERIOD_CLOSED", jsString(period)+" has already been invoiced; leave period out to bill the next invoice", 409)
				}
			}
			record := core.NewObject("id", ID(), "tenantId", account.Get("id"))
			record.Assign(fields)
			record.Set("status", "pending").Set("source", "manual").Set("createdAt", server.Now()).Set("createdBy", principal.Identity.Get("id"))
			item, err := tx.Insert(ctx, BillingCollections.InvoiceItems, record)
			if err != nil {
				return nil, err
			}
			metadata := core.NewObject("description", item.Get("description"), "amountMicros", item.Get("amountMicros"))
			if value := item.Get("period"); truthy(value) {
				metadata.Set("period", value)
			}
			if err := api.audit(ctx, tx, principal, "billing:invoice-item", realm.Get("id"), "billing/invoice-items/"+billingStr(item, "id"), metadata); err != nil {
				return nil, err
			}
			return billingInvoiceItemView(item)
		}, true)
	return Out[apitypes.BillingCreateInvoiceItemOutput]{Value: result}, err
}

// DeleteInvoiceItem is POST {basePath}/billing/deleteInvoiceItem. Deletes a pending invoice item. Root administrators
// only; audited as `billing:invoice-item-delete`.
func (api *BillingAPI) DeleteInvoiceItem(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingDeleteInvoiceItemInput]) (Out[apitypes.BillingDeleteInvoiceItemOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/invoice-items",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			itemID, err := Text(input.Get("itemId"), "itemId")
			if err != nil {
				return nil, err
			}
			item, err := server.Scoped(ctx, tx, BillingCollections.InvoiceItems, itemID, billingStr(realm, "id"))
			if err != nil {
				return nil, err
			}
			if item.Get("status") != "pending" {
				return nil, core.NewIamError("INVALID_TRANSITION", "The item is on a finalized invoice; issue a credit note instead", 409)
			}
			if err := tx.Delete(ctx, BillingCollections.InvoiceItems, billingStr(item, "id")); err != nil {
				return nil, err
			}
			if err := api.audit(ctx, tx, principal, "billing:invoice-item-delete", realm.Get("id"), "billing/invoice-items/"+billingStr(item, "id"),
				core.NewObject("description", item.Get("description"), "amountMicros", item.Get("amountMicros"))); err != nil {
				return nil, err
			}
			return core.NewObject("success", true), nil
		}, true)
	return Out[apitypes.BillingDeleteInvoiceItemOutput]{Value: result}, err
}

// ---------------------------------------------------------------------------------------------------------------
// Plans and subscriptions

// ListPlans is POST {basePath}/billing/listPlans. The platform's plans: fixed monthly fees, per-seat fees and plan
// prices for meters. Other tenants see plans that are not archived; root administrators also see archived plans
// (`includeArchived`) and subscriber counts. Requires iam:billing:read.
func (api *BillingAPI) ListPlans(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingListPlansInput]) (Out[apitypes.BillingListPlansOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:read", "billing/plans",
		func(ctx context.Context, call MutationContext) ([]any, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			root, err := api.rootOf(ctx, tx, realm)
			if err != nil {
				return nil, err
			}
			admin := false
			if realm.Get("parentId") == nil {
				if admin, err = server.RootPrincipal(ctx, tx, principal); err != nil {
					return nil, err
				}
			}
			plans, err := tx.Find(ctx, BillingCollections.Plans, core.NewObject("tenantId", root.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			now := server.Now()
			live := []*core.Object{}
			if admin {
				subscriptions, err := tx.Find(ctx, BillingCollections.Subscriptions, nil, nil)
				if err != nil {
					return nil, err
				}
				for _, subscription := range subscriptions {
					status, err := SubscriptionStatus(subscription, now)
					if err != nil {
						return nil, err
					}
					if status != "ended" {
						live = append(live, subscription)
					}
				}
			}
			shown := []*core.Object{}
			for _, plan := range plans {
				if !truthy(plan.Get("archived")) || (admin && input.Get("includeArchived") == true) {
					shown = append(shown, plan)
				}
			}
			billingSort(shown, billingByName)
			views := []any{}
			for _, plan := range shown {
				var subscribers any = core.Undefined
				if admin {
					count := 0
					for _, subscription := range live {
						if subscription.Get("planId") == plan.Get("id") {
							count++
						}
					}
					subscribers = float64(count)
				}
				view, err := billingPlanView(plan, subscribers)
				if err != nil {
					return nil, err
				}
				views = append(views, view)
			}
			return views, nil
		}, false)
	return Out[apitypes.BillingListPlansOutput]{Value: result}, err
}

// CreatePlan is POST {basePath}/billing/createPlan. Defines a plan on the platform (root) tenant: `key`, `name`,
// `items` (`fee` with `amount`, `seat` with `unitAmount` and `includedSeats`, both billed in `advance` (default) or
// `arrears`; `usage` with a `meter` and `price` that replaces the rate card for subscribers), `trialDays`,
// `selfServe` (account billing managers may subscribe themselves) and `description`. Root administrators only;
// audited as `billing:plan`.
func (api *BillingAPI) CreatePlan(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingCreatePlanInput]) (Out[apitypes.BillingCreatePlanOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/plans",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := billingOnRoot(realm, "Plans"); err != nil {
				return nil, err
			}
			key, err := PlanKey(input.Get("key"))
			if err != nil {
				return nil, err
			}
			existing, err := tx.Find(ctx, BillingCollections.Plans, core.NewObject("tenantId", realm.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			for _, plan := range existing {
				if plan.Get("key") == key {
					return nil, core.NewIamError("CONFLICT", "A plan with this key already exists", 409)
				}
			}
			if len(existing) >= MaxPlansPerTenant {
				return nil, core.NewIamError("LIMIT_EXCEEDED", "At most "+jsString(float64(MaxPlansPerTenant))+" plans", 409)
			}
			body, err := Object(input.Body)
			if err != nil {
				return nil, err
			}
			fields, err := PlanSettings(body, nil)
			if err != nil {
				return nil, err
			}
			now := server.Now()
			actor := principal.Identity.Get("id")
			record := core.NewObject("id", ID(), "tenantId", realm.Get("id"), "uniqueKey", key, "key", key)
			record.Assign(fields)
			record.Set("createdAt", now).Set("createdBy", actor).Set("updatedAt", now).Set("updatedBy", actor)
			plan, err := tx.Insert(ctx, BillingCollections.Plans, record)
			if err != nil {
				return nil, err
			}
			items, _ := plan.Get("items").([]any)
			if err := api.audit(ctx, tx, principal, "billing:plan", realm.Get("id"), "billing/plans/"+billingStr(plan, "id"), core.NewObject(
				"key", key, "name", plan.Get("name"), "items", float64(len(items)), "selfServe", plan.Get("selfServe"),
			)); err != nil {
				return nil, err
			}
			return billingPlanView(plan, 0.0)
		}, true)
	return Out[apitypes.BillingCreatePlanOutput]{Value: result}, err
}

// UpdatePlan is POST {basePath}/billing/updatePlan. Changes a plan (by id or key): any of `name`, `items`,
// `description` (null clears), `trialDays` (null clears), `selfServe`, `archived` (no new subscriptions). Changes
// apply to invoices drawn up afterwards. Root administrators only; audited as `billing:plan-update`.
func (api *BillingAPI) UpdatePlan(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingUpdatePlanInput]) (Out[apitypes.BillingUpdatePlanOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/plans",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := billingOnRoot(realm, "Plans"); err != nil {
				return nil, err
			}
			plan, err := api.planByRef(ctx, tx, realm, input.Get("plan"))
			if err != nil {
				return nil, err
			}
			body, err := Object(input.Body)
			if err != nil {
				return nil, err
			}
			fields, err := PlanSettings(body, plan)
			if err != nil {
				return nil, err
			}
			record := billingWithout(plan, "description", "trialDays").Assign(fields)
			record.Set("updatedAt", server.Now()).Set("updatedBy", principal.Identity.Get("id"))
			next, err := tx.Put(ctx, BillingCollections.Plans, record)
			if err != nil {
				return nil, err
			}
			changed := []any{}
			for _, key := range input.Body.Keys() {
				if key != "tenantId" && key != "plan" {
					changed = append(changed, key)
				}
			}
			if err := api.audit(ctx, tx, principal, "billing:plan-update", realm.Get("id"), "billing/plans/"+billingStr(plan, "id"),
				core.NewObject("key", plan.Get("key"), "fields", changed)); err != nil {
				return nil, err
			}
			return billingPlanView(next, core.Undefined)
		}, true)
	return Out[apitypes.BillingUpdatePlanOutput]{Value: result}, err
}

// ListSubscriptions is POST {basePath}/billing/listSubscriptions. Subscriptions of the billing accounts in the
// tenant's subtree (ended ones with `includeEnded`), newest first. Requires iam:billing:read.
func (api *BillingAPI) ListSubscriptions(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingListSubscriptionsInput]) (Out[apitypes.BillingListSubscriptionsOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:read", "billing/subscriptions",
		func(ctx context.Context, call MutationContext) ([]any, error) {
			tx, realm := call.Tx, call.Tenant
			covered, err := api.coveredAccounts(ctx, tx, realm)
			if err != nil {
				return nil, err
			}
			now := server.Now()
			names := map[string]any{}
			subscriptions, err := tx.Find(ctx, BillingCollections.Subscriptions, nil, nil)
			if err != nil {
				return nil, err
			}
			result := []*core.Object{}
			for _, subscription := range subscriptions {
				if !billingCovers(covered, subscription.Get("tenantId")) {
					continue
				}
				if input.Get("includeEnded") != true {
					status, err := SubscriptionStatus(subscription, now)
					if err != nil {
						return nil, err
					}
					if status == "ended" {
						continue
					}
				}
				tenantID := billingStr(subscription, "tenantId")
				if _, ok := names[tenantID]; !ok {
					name, err := billingTenantName(ctx, tx, subscription.Get("tenantId"))
					if err != nil {
						return nil, err
					}
					names[tenantID] = name
				}
				view, err := billingSubscriptionView(subscription, now, names[tenantID])
				if err != nil {
					return nil, err
				}
				result = append(result, view)
			}
			billingSort(result, func(a, b *core.Object) float64 { return billingNum(b, "startedAt") - billingNum(a, "startedAt") })
			return billingList(result), nil
		}, false)
	return Out[apitypes.BillingListSubscriptionsOutput]{Value: result}, err
}

// Subscribe is POST {basePath}/billing/subscribe. Subscribes the billing account to a plan (id or key) with `seats`
// (default 1). Outside a trial the first month's advance fees and seats are invoiced at once, prorated from today.
// Account billing managers (`iam:billing:manage`) may subscribe to self-serve plans; root administrators to any
// plan, and may set `trialDays` (0 for none). Audited as `billing:subscription`.
func (api *BillingAPI) Subscribe(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingSubscribeInput]) (Out[apitypes.BillingSubscribeOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/subscriptions",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := billingWritable(realm); err != nil {
				return nil, err
			}
			account, err := api.ownAccount(ctx, tx, realm)
			if err != nil {
				return nil, err
			}
			plan, err := api.planByRef(ctx, tx, realm, input.Get("plan"))
			if err != nil {
				return nil, err
			}
			admin, err := api.mayManage(ctx, tx, principal, plan)
			if err != nil {
				return nil, err
			}
			if !isUndefined(input.Get("trialDays")) && !admin {
				return nil, NewOperationDenied("Only root administrators set trial days")
			}
			seats := 1.0
			if value := input.Get("seats"); !isUndefined(value) {
				if seats, err = Integer(value, "seats", 0, 1_000_000); err != nil {
					return nil, err
				}
			}
			options := core.NewObject("seats", seats)
			if value := input.Get("trialDays"); !isUndefined(value) {
				trialDays, err := Integer(value, "trialDays", 0, 365)
				if err != nil {
					return nil, err
				}
				options.Set("trialDays", trialDays)
			}
			subscribed, err := api.service().Subscribe(ctx, tx, account, plan, options, billingStr(principal.Identity, "id"))
			if err != nil {
				return nil, err
			}
			subscription, _ := subscribed.Get("subscription").(*core.Object)
			invoice, _ := subscribed.Get("invoice").(*core.Object)
			metadata := core.NewObject("plan", plan.Get("key"), "seats", seats)
			if value := subscription.Get("trialEndsAt"); !isUndefined(value) {
				metadata.Set("trialEndsAt", value)
			}
			if invoice != nil {
				metadata.Set("invoice", invoice.Get("number")).Set("totalMicros", invoice.Get("totalMicros"))
			}
			if err := api.audit(ctx, tx, principal, "billing:subscription", realm.Get("id"), "billing/subscriptions/"+billingStr(subscription, "id"), metadata); err != nil {
				return nil, err
			}
			now := server.Now()
			view, err := billingSubscriptionView(subscription, now, account.Get("name"))
			if err != nil {
				return nil, err
			}
			out := core.NewObject("subscription", view)
			if invoice != nil {
				summary, err := billingSummary(invoice, now, account.Get("name"))
				if err != nil {
					return nil, err
				}
				out.Set("invoice", summary)
			}
			return out, nil
		}, false)
	return Out[apitypes.BillingSubscribeOutput]{Value: result}, err
}

// scopedSubscription is a subscription of the tenant.
func (api *BillingAPI) scopedSubscription(ctx context.Context, tx core.IamStore, realm *core.Object, subscriptionID any) (*core.Object, error) {
	id, err := Text(subscriptionID, "subscriptionId")
	if err != nil {
		return nil, err
	}
	return api.server.Scoped(ctx, tx, BillingCollections.Subscriptions, id, billingStr(realm, "id"))
}

// subscriptionPlan is `await tx.get(plansCollection, subscription.planId)` (nil when gone).
func billingSubscriptionPlan(ctx context.Context, tx core.IamStore, subscription *core.Object) (*core.Object, error) {
	planID, ok := subscription.Get("planId").(string)
	if !ok {
		return nil, nil
	}
	return tx.Get(ctx, BillingCollections.Plans, planID)
}

// subscriptionChange is the answer of a seat change, cancellation or plan change: the subscription and its
// proration invoice items.
func (api *BillingAPI) subscriptionChange(changed *core.Object, realm *core.Object) (*core.Object, error) {
	subscription, _ := changed.Get("subscription").(*core.Object)
	view, err := billingSubscriptionView(subscription, api.server.Now(), realm.Get("name"))
	if err != nil {
		return nil, err
	}
	items, err := billingInvoiceItemViews(billingRecords(changed.Get("items")))
	if err != nil {
		return nil, err
	}
	return core.NewObject("subscription", view, "invoiceItems", items), nil
}

// UpdateSubscription is POST {basePath}/billing/updateSubscription. Changes a subscription's seats; seats already
// billed in advance for this month are prorated as invoice items on the next invoice. Self-serve plans for account
// billing managers, any for root administrators. Audited as `billing:subscription-update`.
func (api *BillingAPI) UpdateSubscription(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingUpdateSubscriptionInput]) (Out[apitypes.BillingUpdateSubscriptionOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/subscriptions",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			subscription, err := api.scopedSubscription(ctx, tx, realm, input.Get("subscriptionId"))
			if err != nil {
				return nil, err
			}
			plan, err := billingSubscriptionPlan(ctx, tx, subscription)
			if err != nil {
				return nil, err
			}
			if plan != nil {
				if _, err := api.mayManage(ctx, tx, principal, plan); err != nil {
					return nil, err
				}
			}
			seats, err := Integer(input.Get("seats"), "seats", 0, 1_000_000)
			if err != nil {
				return nil, err
			}
			changed, err := api.service().UpdateSeats(ctx, tx, subscription, seats, billingStr(principal.Identity, "id"))
			if err != nil {
				return nil, err
			}
			proration, err := billingProration(billingRecords(changed.Get("items")))
			if err != nil {
				return nil, err
			}
			if err := api.audit(ctx, tx, principal, "billing:subscription-update", realm.Get("id"), "billing/subscriptions/"+billingStr(subscription, "id"), core.NewObject(
				"plan", subscription.Get("planKey"),
				"seats", core.NewObject("before", subscription.Get("seats"), "after", seats),
				"prorationMicros", proration,
			)); err != nil {
				return nil, err
			}
			return api.subscriptionChange(changed, realm)
		}, false)
	return Out[apitypes.BillingUpdateSubscriptionOutput]{Value: result}, err
}

// CancelSubscription is POST {basePath}/billing/cancelSubscription. Cancels a subscription at the end of the month
// (default; it runs until then and can be resumed) or, with `atPeriodEnd: false`, now: the unused part of this
// month's advance charges is credited on the next invoice. Account billing managers cancel self-serve plans at the
// end of the month; root administrators any, either way. Audited as `billing:subscription-cancel`.
func (api *BillingAPI) CancelSubscription(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingCancelSubscriptionInput]) (Out[apitypes.BillingCancelSubscriptionOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/subscriptions",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			subscription, err := api.scopedSubscription(ctx, tx, realm, input.Get("subscriptionId"))
			if err != nil {
				return nil, err
			}
			atPeriodEnd := true
			if value := input.Get("atPeriodEnd"); !isUndefined(value) {
				flag, ok := value.(bool)
				if !ok {
					return nil, invalidInput("atPeriodEnd must be a boolean")
				}
				atPeriodEnd = flag
			}
			plan, err := billingSubscriptionPlan(ctx, tx, subscription)
			if err != nil {
				return nil, err
			}
			var admin bool
			if plan != nil {
				admin, err = api.mayManage(ctx, tx, principal, plan)
			} else {
				admin, err = server.RootPrincipal(ctx, tx, principal)
			}
			if err != nil {
				return nil, err
			}
			if !atPeriodEnd && !admin {
				return nil, NewOperationDenied("Only root administrators cancel a subscription immediately")
			}
			changed, err := api.service().CancelSubscription(ctx, tx, subscription, atPeriodEnd, billingStr(principal.Identity, "id"))
			if err != nil {
				return nil, err
			}
			proration, err := billingProration(billingRecords(changed.Get("items")))
			if err != nil {
				return nil, err
			}
			next, _ := changed.Get("subscription").(*core.Object)
			if err := api.audit(ctx, tx, principal, "billing:subscription-cancel", realm.Get("id"), "billing/subscriptions/"+billingStr(subscription, "id"), core.NewObject(
				"plan", subscription.Get("planKey"), "atPeriodEnd", atPeriodEnd, "endsAt", coalesce(next.Get("endsAt"), nil),
				"prorationMicros", proration,
			)); err != nil {
				return nil, err
			}
			return api.subscriptionChange(changed, realm)
		}, false)
	return Out[apitypes.BillingCancelSubscriptionOutput]{Value: result}, err
}

// ResumeSubscription is POST {basePath}/billing/resumeSubscription. Undoes a cancellation at the end of the month
// before it takes effect. Audited as `billing:subscription-resume`.
func (api *BillingAPI) ResumeSubscription(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingResumeSubscriptionInput]) (Out[apitypes.BillingResumeSubscriptionOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/subscriptions",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			subscription, err := api.scopedSubscription(ctx, tx, realm, input.Get("subscriptionId"))
			if err != nil {
				return nil, err
			}
			plan, err := billingSubscriptionPlan(ctx, tx, subscription)
			if err != nil {
				return nil, err
			}
			if plan != nil {
				if _, err := api.mayManage(ctx, tx, principal, plan); err != nil {
					return nil, err
				}
			}
			next, err := api.service().ResumeSubscription(ctx, tx, subscription)
			if err != nil {
				return nil, err
			}
			if err := api.audit(ctx, tx, principal, "billing:subscription-resume", realm.Get("id"), "billing/subscriptions/"+billingStr(subscription, "id"),
				core.NewObject("plan", subscription.Get("planKey"))); err != nil {
				return nil, err
			}
			return billingSubscriptionView(next, server.Now(), realm.Get("name"))
		}, false)
	return Out[apitypes.BillingResumeSubscriptionOutput]{Value: result}, err
}

// ChangePlan is POST {basePath}/billing/changePlan. Moves a subscription to another plan (id or key) now, keeping
// its seats and what is left of its trial; the old plan's unused advance charges are credited and the new plan's
// charges for the rest of the month added as invoice items for the next invoice. Both plans must be self-serve for
// account billing managers. Audited as `billing:subscription-plan-change`.
func (api *BillingAPI) ChangePlan(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingChangePlanInput]) (Out[apitypes.BillingChangePlanOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/subscriptions",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := billingWritable(realm); err != nil {
				return nil, err
			}
			subscription, err := api.scopedSubscription(ctx, tx, realm, input.Get("subscriptionId"))
			if err != nil {
				return nil, err
			}
			current, err := billingSubscriptionPlan(ctx, tx, subscription)
			if err != nil {
				return nil, err
			}
			plan, err := api.planByRef(ctx, tx, realm, input.Get("plan"))
			if err != nil {
				return nil, err
			}
			plans := []*core.Object{plan}
			if current != nil {
				plans = []*core.Object{current, plan}
			}
			if _, err := api.mayManage(ctx, tx, principal, plans...); err != nil {
				return nil, err
			}
			changed, err := api.service().ChangePlan(ctx, tx, subscription, plan, billingStr(principal.Identity, "id"))
			if err != nil {
				return nil, err
			}
			proration, err := billingProration(billingRecords(changed.Get("items")))
			if err != nil {
				return nil, err
			}
			next, _ := changed.Get("subscription").(*core.Object)
			if err := api.audit(ctx, tx, principal, "billing:subscription-plan-change", realm.Get("id"), "billing/subscriptions/"+billingStr(next, "id"), core.NewObject(
				"from", subscription.Get("planKey"), "to", plan.Get("key"), "previousSubscriptionId", subscription.Get("id"),
				"prorationMicros", proration,
			)); err != nil {
				return nil, err
			}
			return api.subscriptionChange(changed, realm)
		}, false)
	return Out[apitypes.BillingChangePlanOutput]{Value: result}, err
}

// ---------------------------------------------------------------------------------------------------------------
// Coupons and discounts

// ListCoupons is POST {basePath}/billing/listCoupons. The platform's coupons, newest first. Called on the root
// tenant; root administrators only.
func (api *BillingAPI) ListCoupons(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingListCouponsInput]) (Out[apitypes.BillingListCouponsOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:read", "billing/coupons",
		func(ctx context.Context, call MutationContext) ([]any, error) {
			realm := call.Tenant
			if err := billingOnRoot(realm, "Coupons"); err != nil {
				return nil, err
			}
			now := server.Now()
			coupons, err := call.Tx.Find(ctx, BillingCollections.Coupons, core.NewObject("tenantId", realm.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			billingSort(coupons, func(a, b *core.Object) float64 { return billingNum(b, "createdAt") - billingNum(a, "createdAt") })
			views := []any{}
			for _, coupon := range coupons {
				view, err := billingCouponView(coupon, now)
				if err != nil {
					return nil, err
				}
				views = append(views, view)
			}
			return views, nil
		}, true)
	return Out[apitypes.BillingListCouponsOutput]{Value: result}, err
}

// CreateCoupon is POST {basePath}/billing/createCoupon. Creates a coupon on the platform (root) tenant: a `code`
// accounts redeem, `percentOff` or `amountOff` (currency units), a `duration` (`once`: the next invoice;
// `repeating`: invoices for `durationInMonths` months from redemption; `forever`), and optional `maxRedemptions` and
// `redeemBy`. Root administrators only; audited as `billing:coupon`.
func (api *BillingAPI) CreateCoupon(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingCreateCouponInput]) (Out[apitypes.BillingCreateCouponOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/coupons",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := billingOnRoot(realm, "Coupons"); err != nil {
				return nil, err
			}
			now := server.Now()
			body, err := Object(input.Body)
			if err != nil {
				return nil, err
			}
			fields, err := CouponSettings(body, now)
			if err != nil {
				return nil, err
			}
			uniqueKey := "code:" + billingStr(fields, "code")
			taken, err := tx.Find(ctx, BillingCollections.Coupons, core.NewObject("tenantId", realm.Get("id"), "uniqueKey", uniqueKey), nil)
			if err != nil {
				return nil, err
			}
			if len(taken) > 0 {
				return nil, core.NewIamError("CONFLICT", "A coupon with this code already exists", 409)
			}
			record := core.NewObject("id", ID(), "tenantId", realm.Get("id"), "uniqueKey", uniqueKey)
			record.Assign(fields)
			record.Set("redemptions", 0.0).Set("active", true).Set("createdAt", now).Set("createdBy", principal.Identity.Get("id"))
			coupon, err := tx.Insert(ctx, BillingCollections.Coupons, record)
			if err != nil {
				return nil, err
			}
			metadata := core.NewObject("code", coupon.Get("code"))
			if value := coupon.Get("percentOff"); !isUndefined(value) {
				metadata.Set("percentOff", value)
			}
			if value := coupon.Get("amountOffMicros"); !isUndefined(value) {
				metadata.Set("amountOffMicros", value)
			}
			metadata.Set("duration", coupon.Get("duration"))
			if err := api.audit(ctx, tx, principal, "billing:coupon", realm.Get("id"), "billing/coupons/"+billingStr(coupon, "id"), metadata); err != nil {
				return nil, err
			}
			return billingCouponView(coupon, now)
		}, true)
	return Out[apitypes.BillingCreateCouponOutput]{Value: result}, err
}

// DeactivateCoupon is POST {basePath}/billing/deactivateCoupon. Stops a coupon (by code) from being redeemed;
// accounts that redeemed it keep their discount. Root administrators only; audited as `billing:coupon-deactivate`.
func (api *BillingAPI) DeactivateCoupon(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingDeactivateCouponInput]) (Out[apitypes.BillingDeactivateCouponOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/coupons",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := billingOnRoot(realm, "Coupons"); err != nil {
				return nil, err
			}
			code, err := CouponCode(input.Get("code"))
			if err != nil {
				return nil, err
			}
			found, err := tx.Find(ctx, BillingCollections.Coupons, core.NewObject("tenantId", realm.Get("id"), "uniqueKey", "code:"+code), nil)
			if err != nil {
				return nil, err
			}
			if len(found) == 0 {
				return nil, core.NewIamError("NOT_FOUND", "Coupon not found", 404)
			}
			coupon := found[0]
			next, err := tx.Put(ctx, BillingCollections.Coupons, coupon.Spread(core.NewObject("active", false)))
			if err != nil {
				return nil, err
			}
			if err := api.audit(ctx, tx, principal, "billing:coupon-deactivate", realm.Get("id"), "billing/coupons/"+billingStr(coupon, "id"),
				core.NewObject("code", code)); err != nil {
				return nil, err
			}
			return billingCouponView(next, server.Now())
		}, true)
	return Out[apitypes.BillingDeactivateCouponOutput]{Value: result}, err
}

// RedeemCoupon is POST {basePath}/billing/redeemCoupon. Redeems a coupon code for the billing account: its discount
// applies to the account's invoices for the coupon's duration, after the contract discount. Once per coupon per
// account. Requires iam:billing:manage on the account; audited as `billing:coupon-redeem`.
func (api *BillingAPI) RedeemCoupon(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingRedeemCouponInput]) (Out[apitypes.BillingRedeemCouponOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/discounts",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := billingWritable(realm); err != nil {
				return nil, err
			}
			account, err := api.ownAccount(ctx, tx, realm)
			if err != nil {
				return nil, err
			}
			code, err := CouponCode(input.Get("code"))
			if err != nil {
				return nil, err
			}
			root, err := api.rootOf(ctx, tx, realm)
			if err != nil {
				return nil, err
			}
			now := server.Now()
			found, err := tx.Find(ctx, BillingCollections.Coupons, core.NewObject("tenantId", root.Get("id"), "uniqueKey", "code:"+code), nil)
			if err != nil {
				return nil, err
			}
			var coupon *core.Object
			if len(found) > 0 {
				coupon = found[0]
			}
			if coupon != nil {
				redeemed, err := tx.Find(ctx, BillingCollections.Discounts, core.NewObject("tenantId", account.Get("id"), "uniqueKey", "coupon:"+billingStr(coupon, "id")), nil)
				if err != nil {
					return nil, err
				}
				if len(redeemed) > 0 {
					return nil, core.NewIamError("CONFLICT", "The account has already redeemed this code", 409)
				}
			}
			// Unknown, inactive, expired and used-up codes look the same to the account.
			valid := coupon != nil
			if valid {
				view, err := billingCouponView(coupon, now)
				if err != nil {
					return nil, err
				}
				valid = view.Get("active") == true
			}
			if !valid {
				return nil, core.NewIamError("NOT_FOUND", "This code is not valid", 404)
			}
			if _, err := tx.Put(ctx, BillingCollections.Coupons, coupon.Spread(core.NewObject("redemptions", billingNum(coupon, "redemptions")+1))); err != nil {
				return nil, err
			}
			record := core.NewObject("id", ID(), "tenantId", account.Get("id"), "uniqueKey", "coupon:"+billingStr(coupon, "id"),
				"couponId", coupon.Get("id"), "code", coupon.Get("code"), "name", coupon.Get("name"))
			if value := coupon.Get("percentOff"); !isUndefined(value) {
				record.Set("percentOff", value)
			}
			if value := coupon.Get("amountOffMicros"); !isUndefined(value) {
				record.Set("amountOffMicros", value)
			}
			record.Set("duration", coupon.Get("duration"))
			if value := coupon.Get("durationInMonths"); !isUndefined(value) {
				record.Set("durationInMonths", value)
			}
			record.Set("appliedInvoices", 0.0).Set("redeemedAt", now).Set("redeemedBy", principal.Identity.Get("id"))
			discount, err := tx.Insert(ctx, BillingCollections.Discounts, record)
			if err != nil {
				return nil, err
			}
			if err := api.audit(ctx, tx, principal, "billing:coupon-redeem", realm.Get("id"), "billing/discounts/"+billingStr(discount, "id"),
				core.NewObject("code", code, "couponId", coupon.Get("id"))); err != nil {
				return nil, err
			}
			period, err := api.service().CurrentPeriod()
			if err != nil {
				return nil, err
			}
			return billingDiscountView(discount, period, billingStr(api.settings(), "timeZone"))
		}, false)
	return Out[apitypes.BillingRedeemCouponOutput]{Value: result}, err
}

// ListDiscounts is POST {basePath}/billing/listDiscounts. Discounts (redeemed coupons) of the billing accounts in the
// tenant's subtree. Requires iam:billing:read.
func (api *BillingAPI) ListDiscounts(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingListDiscountsInput]) (Out[apitypes.BillingListDiscountsOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:read", "billing/discounts",
		func(ctx context.Context, call MutationContext) ([]any, error) {
			tx, realm := call.Tx, call.Tenant
			covered, err := api.coveredAccounts(ctx, tx, realm)
			if err != nil {
				return nil, err
			}
			period, err := api.service().CurrentPeriod()
			if err != nil {
				return nil, err
			}
			all, err := tx.Find(ctx, BillingCollections.Discounts, nil, nil)
			if err != nil {
				return nil, err
			}
			discounts := []*core.Object{}
			for _, discount := range all {
				if billingCovers(covered, discount.Get("tenantId")) {
					discounts = append(discounts, discount)
				}
			}
			billingSort(discounts, func(a, b *core.Object) float64 { return billingNum(b, "redeemedAt") - billingNum(a, "redeemedAt") })
			timeZone := billingStr(api.settings(), "timeZone")
			views := []any{}
			for _, discount := range discounts {
				view, err := billingDiscountView(discount, period, timeZone)
				if err != nil {
					return nil, err
				}
				views = append(views, view)
			}
			return views, nil
		}, false)
	return Out[apitypes.BillingListDiscountsOutput]{Value: result}, err
}

// RemoveDiscount is POST {basePath}/billing/removeDiscount. Ends a discount of the billing account now. Root
// administrators only; audited as `billing:discount-remove`.
func (api *BillingAPI) RemoveDiscount(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingRemoveDiscountInput]) (Out[apitypes.BillingRemoveDiscountOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:billing:manage", "billing/discounts",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			discountID, err := Text(input.Get("discountId"), "discountId")
			if err != nil {
				return nil, err
			}
			discount, err := server.Scoped(ctx, tx, BillingCollections.Discounts, discountID, billingStr(realm, "id"))
			if err != nil {
				return nil, err
			}
			if !isUndefined(discount.Get("endedAt")) {
				return nil, core.NewIamError("INVALID_TRANSITION", "The discount has already ended", 409)
			}
			next, err := tx.Put(ctx, BillingCollections.Discounts, discount.Spread(core.NewObject("endedAt", server.Now())))
			if err != nil {
				return nil, err
			}
			if err := api.audit(ctx, tx, principal, "billing:discount-remove", realm.Get("id"), "billing/discounts/"+billingStr(discount, "id"),
				core.NewObject("code", discount.Get("code"))); err != nil {
				return nil, err
			}
			period, err := api.service().CurrentPeriod()
			if err != nil {
				return nil, err
			}
			return billingDiscountView(next, period, billingStr(api.settings(), "timeZone"))
		}, true)
	return Out[apitypes.BillingRemoveDiscountOutput]{Value: result}, err
}

// ---------------------------------------------------------------------------------------------------------------
// iam.billing

// IamBilling is api/billing.ts IamBilling: trusted, credential-free billing for the deployment's own server code
// (`iam.billing`).
type IamBilling struct {
	server *ServerContext
	// Settings The deployment's billing settings (currency, time zone, ...).
	Settings *core.Object
}

// service is billingServiceOf(ctx).
func (s *IamBilling) service() *BillingService { return BillingServiceOf(s.server) }

// Record (api/billing.ts IamBilling.record): Records usage without a credential and without an audit event (the hot
// path for metering).
func (s *IamBilling) Record(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	return core.Transact(ctx, s.server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		extra := core.NewObject()
		if input.Get("enforceBudgets") == true {
			extra.Set("enforceBudgets", true)
		}
		return s.service().Record(ctx, tx, input, "deployment", extra)
	})
}

// RecordMany (api/billing.ts IamBilling.recordMany): Records up to 1000 events in one transaction.
func (s *IamBilling) RecordMany(ctx context.Context, events []*core.Object) (result []*core.Object, err error) {
	if len(events) == 0 || len(events) > 1000 {
		return nil, invalidInput("events must list 1-1000 usage events")
	}
	return core.Transact(ctx, s.server.Store, func(ctx context.Context, tx core.IamStore) ([]*core.Object, error) {
		receipts := []*core.Object{}
		for _, event := range events {
			receipt, err := s.service().Record(ctx, tx, event, "deployment", core.NewObject())
			if err != nil {
				return nil, err
			}
			receipts = append(receipts, receipt)
		}
		return receipts, nil
	})
}

// Check (api/billing.ts IamBilling.check): Whether usage by `identityId` in the tenant is within every enforced
// budget that covers it.
func (s *IamBilling) Check(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	return core.Transact(ctx, s.server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		tenantID, err := Text(input.Get("tenantId"), "tenantId")
		if err != nil {
			return nil, err
		}
		realm, err := s.server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		query := core.NewObject()
		if value := input.Get("identityId"); !isUndefined(value) {
			query.Set("identityId", value)
		}
		if value := input.Get("meter"); !isUndefined(value) {
			query.Set("meter", value)
		}
		return s.service().Check(ctx, tx, realm, query)
	})
}

// Spend (api/billing.ts IamBilling.spend): A spend report for a tenant's subtree.
func (s *IamBilling) Spend(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	return core.Transact(ctx, s.server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		tenantID, err := Text(input.Get("tenantId"), "tenantId")
		if err != nil {
			return nil, err
		}
		realm, err := s.server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		return s.service().Report(ctx, tx, realm, billingWithout(input, "tenantId"), nil, nil)
	})
}

// RecordSeats (api/billing.ts IamBilling.recordSeats): Daily seat recording (scheduler job).
func (s *IamBilling) RecordSeats(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	return s.service().RecordSeats(ctx, input)
}

// CheckBudgets (api/billing.ts IamBilling.checkBudgets): Budget threshold and forecast alerts (scheduler job).
func (s *IamBilling) CheckBudgets(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	return s.service().CheckBudgets(ctx, input)
}

// ClosePeriod (api/billing.ts IamBilling.closePeriod): Issues statements for the previous (or a given past) period
// and sweeps old usage events (scheduler job).
func (s *IamBilling) ClosePeriod(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	return s.service().ClosePeriod(ctx, input)
}

// DetectAnomalies (api/billing.ts IamBilling.detectAnomalies): Spend-spike alerts for every billing account for
// yesterday (scheduler job, daily).
func (s *IamBilling) DetectAnomalies(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	return s.service().DetectAnomalies(ctx, input)
}

// SendPaymentReminders (api/billing.ts IamBilling.sendPaymentReminders): Payment reminders for unpaid invoices at
// `billing.paymentReminderDays` (scheduler job, daily).
func (s *IamBilling) SendPaymentReminders(ctx context.Context) (result *core.Object, err error) {
	return s.service().SendPaymentReminders(ctx)
}

// RecordPayment (api/billing.ts IamBilling.recordPayment): Records a payment from a payment processor (a Stripe
// webhook, a bank feed) against an invoice by id or number. `idempotencyKey` (the processor's payment id) makes
// redelivery safe: a known key returns the invoice unchanged.
func (s *IamBilling) RecordPayment(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	server := s.server
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		var statement *core.Object
		if value := input.Get("statementId"); !isUndefined(value) {
			id, err := Text(value, "statementId")
			if err != nil {
				return nil, err
			}
			if statement, err = tx.Get(ctx, BillingCollections.Statements, id); err != nil {
				return nil, err
			}
		} else if value := input.Get("number"); !isUndefined(value) {
			number, err := Text(value, "number", 64)
			if err != nil {
				return nil, err
			}
			found, err := tx.Find(ctx, BillingCollections.Statements, core.NewObject("number", number), nil)
			if err != nil {
				return nil, err
			}
			if len(found) > 0 {
				statement = found[0]
			}
		} else {
			return nil, invalidInput("Give statementId or number")
		}
		if statement == nil {
			return nil, core.NewIamError("NOT_FOUND", "Statement not found", 404)
		}
		var key any = core.Undefined
		if value := input.Get("idempotencyKey"); !isUndefined(value) {
			text, err := Text(value, "idempotencyKey", 128)
			if err != nil {
				return nil, err
			}
			key = text
		}
		// The processor's payment id doubles as the payment reference.
		if !isUndefined(key) {
			for _, payment := range billingRecords(statement.Get("payments")) {
				if payment.Get("reference") == key {
					return core.NewObject("statement", statement, "duplicate", true), nil
				}
			}
		}
		payment := billingWithout(input, "idempotencyKey", "statementId", "number")
		if !isUndefined(key) {
			payment.Set("reference", key)
		}
		recorded, err := s.service().RecordPayment(ctx, tx, statement, payment, "deployment")
		if err != nil {
			return nil, err
		}
		next, _ := recorded.Get("statement").(*core.Object)
		paid, _ := recorded.Get("payment").(*core.Object)
		metadata := core.NewObject("number", statement.Get("number"), "amountMicros", paid.Get("amountMicros"), "method", paid.Get("method"))
		if value := paid.Get("reference"); truthy(value) {
			metadata.Set("reference", value)
		}
		metadata.Set("status", next.Get("status"))
		if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
			"id", ID(),
			"tenantId", statement.Get("tenantId"),
			"actorId", "deployment-operator",
			"action", "billing:payment",
			"resourceId", "billing/statements/"+billingStr(statement, "id"),
			"timestamp", server.Now(),
			"outcome", "allow",
			"metadata", metadata,
		)); err != nil {
			return nil, err
		}
		return recorded.Spread().Set("duplicate", false), nil
	})
}

// CreateBillingRuntime builds the IamBilling (api/billing.ts createBillingRuntime).
func CreateBillingRuntime(server *ServerContext) *IamBilling {
	return &IamBilling{server: server, Settings: BillingServiceOf(server).Settings}
}
