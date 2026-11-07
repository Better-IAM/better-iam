package server

// Skeleton of packages/server/src/api/billing.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

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

// Accounts is POST {basePath}/billing/accounts. Lists the billing accounts in the tenant's subtree with this month's billable spend, projection, available credit and latest statement.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) Accounts(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingAccountsInput]) (Out[apitypes.BillingAccountsOutput], error) {
	return Out[apitypes.BillingAccountsOutput]{}, notImplemented("billing.accounts")
}

// Anomalies is POST {basePath}/billing/anomalies. Lists the people, teams and meters whose spend on one day jumped far above their usual daily spend.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) Anomalies(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingAnomaliesInput]) (Out[apitypes.BillingAnomaliesOutput], error) {
	return Out[apitypes.BillingAnomaliesOutput]{}, notImplemented("billing.anomalies")
}

// CancelSubscription is POST {basePath}/billing/cancelSubscription. Cancels a subscription at the end of the month (default) or now.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) CancelSubscription(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingCancelSubscriptionInput]) (Out[apitypes.BillingCancelSubscriptionOutput], error) {
	return Out[apitypes.BillingCancelSubscriptionOutput]{}, notImplemented("billing.cancelSubscription")
}

// ChangePlan is POST {basePath}/billing/changePlan. Moves a subscription to another plan now, keeping its seats and what is left of its trial.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) ChangePlan(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingChangePlanInput]) (Out[apitypes.BillingChangePlanOutput], error) {
	return Out[apitypes.BillingChangePlanOutput]{}, notImplemented("billing.changePlan")
}

// Check is POST {basePath}/billing/check. Reports whether the caller's own usage is within every enforced budget that covers it.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) Check(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingCheckInput]) (Out[apitypes.BillingCheckOutput], error) {
	return Out[apitypes.BillingCheckOutput]{}, notImplemented("billing.check")
}

// ClosePeriod is POST {basePath}/billing/closePeriod. Issues statements for a month that has ended, for every billing account or only accountId's.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) ClosePeriod(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingClosePeriodInput]) (Out[apitypes.BillingClosePeriodOutput], error) {
	return Out[apitypes.BillingClosePeriodOutput]{}, notImplemented("billing.closePeriod")
}

// CreateBudget is POST {basePath}/billing/createBudget. Creates a spend budget for the tenant, a tenant below it, a team, a department or a person, per month, quarter or year.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) CreateBudget(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingCreateBudgetInput]) (Out[apitypes.BillingCreateBudgetOutput], error) {
	return Out[apitypes.BillingCreateBudgetOutput]{}, notImplemented("billing.createBudget")
}

// CreateCoupon is POST {basePath}/billing/createCoupon. Creates a coupon accounts can redeem by code.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) CreateCoupon(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingCreateCouponInput]) (Out[apitypes.BillingCreateCouponOutput], error) {
	return Out[apitypes.BillingCreateCouponOutput]{}, notImplemented("billing.createCoupon")
}

// CreateCreditNote is POST {basePath}/billing/createCreditNote. Issues a credit note against a finalized, paid or uncollectible invoice.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) CreateCreditNote(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingCreateCreditNoteInput]) (Out[apitypes.BillingCreateCreditNoteOutput], error) {
	return Out[apitypes.BillingCreateCreditNoteOutput]{}, notImplemented("billing.createCreditNote")
}

// CreateInvoiceItem is POST {basePath}/billing/createInvoiceItem. Adds a one-off charge, or with a negative amount a credit, to the billing account's next invoice.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) CreateInvoiceItem(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingCreateInvoiceItemInput]) (Out[apitypes.BillingCreateInvoiceItemOutput], error) {
	return Out[apitypes.BillingCreateInvoiceItemOutput]{}, notImplemented("billing.createInvoiceItem")
}

// CreateMeter is POST {basePath}/billing/createMeter. Defines a usage meter: a platform meter on the root tenant, a chargeback meter for the tenant's subtree elsewhere.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) CreateMeter(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingCreateMeterInput]) (Out[apitypes.BillingCreateMeterOutput], error) {
	return Out[apitypes.BillingCreateMeterOutput]{}, notImplemented("billing.createMeter")
}

// CreatePlan is POST {basePath}/billing/createPlan. Defines a plan on the platform (root) tenant.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) CreatePlan(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingCreatePlanInput]) (Out[apitypes.BillingCreatePlanOutput], error) {
	return Out[apitypes.BillingCreatePlanOutput]{}, notImplemented("billing.createPlan")
}

// DeactivateCoupon is POST {basePath}/billing/deactivateCoupon. Stops a coupon (by code) from being redeemed; accounts that redeemed it keep their discount.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) DeactivateCoupon(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingDeactivateCouponInput]) (Out[apitypes.BillingDeactivateCouponOutput], error) {
	return Out[apitypes.BillingDeactivateCouponOutput]{}, notImplemented("billing.deactivateCoupon")
}

// DeleteBudget is POST {basePath}/billing/deleteBudget. Deletes a budget and its alert history.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) DeleteBudget(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingDeleteBudgetInput]) (Out[apitypes.BillingDeleteBudgetOutput], error) {
	return Out[apitypes.BillingDeleteBudgetOutput]{}, notImplemented("billing.deleteBudget")
}

// DeleteInvoiceItem is POST {basePath}/billing/deleteInvoiceItem. Deletes a pending invoice item.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) DeleteInvoiceItem(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingDeleteInvoiceItemInput]) (Out[apitypes.BillingDeleteInvoiceItemOutput], error) {
	return Out[apitypes.BillingDeleteInvoiceItemOutput]{}, notImplemented("billing.deleteInvoiceItem")
}

// DeleteMeter is POST {basePath}/billing/deleteMeter. Deletes a meter that has never recorded usage, with its prices.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) DeleteMeter(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingDeleteMeterInput]) (Out[apitypes.BillingDeleteMeterOutput], error) {
	return Out[apitypes.BillingDeleteMeterOutput]{}, notImplemented("billing.deleteMeter")
}

// DeleteProfile is POST {basePath}/billing/deleteProfile. Removes a billing profile, so the tenant's usage rolls into its parent's account again.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) DeleteProfile(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingDeleteProfileInput]) (Out[apitypes.BillingDeleteProfileOutput], error) {
	return Out[apitypes.BillingDeleteProfileOutput]{}, notImplemented("billing.deleteProfile")
}

// DepartmentSpend is POST {basePath}/billing/departmentSpend. Reports a department's spend, with the departments below it, grouped by identity by default.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) DepartmentSpend(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingDepartmentSpendInput]) (Out[apitypes.BillingDepartmentSpendOutput], error) {
	return Out[apitypes.BillingDepartmentSpendOutput]{}, notImplemented("billing.departmentSpend")
}

// ExportSpend is POST {basePath}/billing/exportSpend. Returns a spend report as a CSV file: one row per group with the amount, share, events and a column per meter's quantity.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) ExportSpend(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingExportSpendInput]) (Out[apitypes.BillingExportSpendOutput], error) {
	return Out[apitypes.BillingExportSpendOutput]{}, notImplemented("billing.exportSpend")
}

// ExportStatement is POST {basePath}/billing/exportStatement. Returns a statement as a CSV file: its lines, credit and total, then the breakdown by project, team, department and person.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) ExportStatement(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingExportStatementInput]) (Out[apitypes.BillingExportStatementOutput], error) {
	return Out[apitypes.BillingExportStatementOutput]{}, notImplemented("billing.exportStatement")
}

// FinalizeInvoice is POST {basePath}/billing/finalizeInvoice. Finalizes a draft invoice: recomputes it with the latest usage and invoice items, numbers it, seals it and emails it.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) FinalizeInvoice(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingFinalizeInvoiceInput]) (Out[apitypes.BillingFinalizeInvoiceOutput], error) {
	return Out[apitypes.BillingFinalizeInvoiceOutput]{}, notImplemented("billing.finalizeInvoice")
}

// GetProfile is POST {basePath}/billing/getProfile. Returns the billing profile of the tenant (or of targetTenantId below it) and the account that pays for it.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) GetProfile(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingGetProfileInput]) (Out[apitypes.BillingGetProfileOutput], error) {
	return Out[apitypes.BillingGetProfileOutput]{}, notImplemented("billing.getProfile")
}

// GetStatement is POST {basePath}/billing/getStatement. Returns one statement with its lines, credit, breakdown and bill-to details, re-checking its content hash.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) GetStatement(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingGetStatementInput]) (Out[apitypes.BillingGetStatementOutput], error) {
	return Out[apitypes.BillingGetStatementOutput]{}, notImplemented("billing.getStatement")
}

// GetTerms is POST {basePath}/billing/getTerms. Returns the contract terms of the tenant's billing account: discount, minimum monthly commitment and tax.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) GetTerms(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingGetTermsInput]) (Out[apitypes.BillingGetTermsOutput], error) {
	return Out[apitypes.BillingGetTermsOutput]{}, notImplemented("billing.getTerms")
}

// GrantCredit is POST {basePath}/billing/grantCredit. Grants credit to a billing account, which its statements draw on, earliest expiry first.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) GrantCredit(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingGrantCreditInput]) (Out[apitypes.BillingGrantCreditOutput], error) {
	return Out[apitypes.BillingGrantCreditOutput]{}, notImplemented("billing.grantCredit")
}

// ListBudgets is POST {basePath}/billing/listBudgets. Lists the tenant's budgets with their spend, projection and the thresholds reached in the current window.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) ListBudgets(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingListBudgetsInput]) (Out[apitypes.BillingListBudgetsOutput], error) {
	return Out[apitypes.BillingListBudgetsOutput]{}, notImplemented("billing.listBudgets")
}

// ListCoupons is POST {basePath}/billing/listCoupons. Lists the platform's coupons, newest first, with their redemptions.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) ListCoupons(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingListCouponsInput]) (Out[apitypes.BillingListCouponsOutput], error) {
	return Out[apitypes.BillingListCouponsOutput]{}, notImplemented("billing.listCoupons")
}

// ListCreditNotes is POST {basePath}/billing/listCreditNotes. Lists the credit notes of the billing accounts in the tenant's subtree, or of one statementId, newest first.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) ListCreditNotes(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingListCreditNotesInput]) (Out[apitypes.BillingListCreditNotesOutput], error) {
	return Out[apitypes.BillingListCreditNotesOutput]{}, notImplemented("billing.listCreditNotes")
}

// ListCredits is POST {basePath}/billing/listCredits. Lists the credit of the tenant's billing account with the available balance.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) ListCredits(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingListCreditsInput]) (Out[apitypes.BillingListCreditsOutput], error) {
	return Out[apitypes.BillingListCreditsOutput]{}, notImplemented("billing.listCredits")
}

// ListDiscounts is POST {basePath}/billing/listDiscounts. Lists the discounts (redeemed coupons) of the billing accounts in the tenant's subtree.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) ListDiscounts(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingListDiscountsInput]) (Out[apitypes.BillingListDiscountsOutput], error) {
	return Out[apitypes.BillingListDiscountsOutput]{}, notImplemented("billing.listDiscounts")
}

// ListInvoiceItems is POST {basePath}/billing/listInvoiceItems. Lists invoice items of the billing accounts in the tenant's subtree, newest first, optionally by status.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) ListInvoiceItems(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingListInvoiceItemsInput]) (Out[apitypes.BillingListInvoiceItemsOutput], error) {
	return Out[apitypes.BillingListInvoiceItemsOutput]{}, notImplemented("billing.listInvoiceItems")
}

// ListMeters is POST {basePath}/billing/listMeters. Lists the meters that reach the tenant with the price that applies to its billing account this month.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) ListMeters(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingListMetersInput]) (Out[apitypes.BillingListMetersOutput], error) {
	return Out[apitypes.BillingListMetersOutput]{}, notImplemented("billing.listMeters")
}

// ListPlans is POST {basePath}/billing/listPlans. Lists the platform's plans with their fees, seats and meter prices.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) ListPlans(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingListPlansInput]) (Out[apitypes.BillingListPlansOutput], error) {
	return Out[apitypes.BillingListPlansOutput]{}, notImplemented("billing.listPlans")
}

// ListPrices is POST {basePath}/billing/listPrices. Returns a meter's rate card as the tenant may see it, and the entry that prices its account this month.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) ListPrices(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingListPricesInput]) (Out[apitypes.BillingListPricesOutput], error) {
	return Out[apitypes.BillingListPricesOutput]{}, notImplemented("billing.listPrices")
}

// ListStatements is POST {basePath}/billing/listStatements. Lists the statements of the billing accounts in the tenant's subtree (all of them for the root), newest month first.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) ListStatements(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingListStatementsInput]) (Out[apitypes.BillingListStatementsOutput], error) {
	return Out[apitypes.BillingListStatementsOutput]{}, notImplemented("billing.listStatements")
}

// ListSubscriptions is POST {basePath}/billing/listSubscriptions. Lists the subscriptions of the billing accounts in the tenant's subtree, newest first.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) ListSubscriptions(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingListSubscriptionsInput]) (Out[apitypes.BillingListSubscriptionsOutput], error) {
	return Out[apitypes.BillingListSubscriptionsOutput]{}, notImplemented("billing.listSubscriptions")
}

// ListUsage is POST {basePath}/billing/listUsage. Lists raw usage events recorded in the tenant for a month, newest first.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) ListUsage(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingListUsageInput]) (Out[apitypes.BillingListUsageOutput], error) {
	return Out[apitypes.BillingListUsageOutput]{}, notImplemented("billing.listUsage")
}

// MarkPaid is POST {basePath}/billing/markPaid. Marks a finalized or uncollectible statement paid by recording a manual payment of the amount due, with an optional reference.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) MarkPaid(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingMarkPaidInput]) (Out[apitypes.BillingMarkPaidOutput], error) {
	return Out[apitypes.BillingMarkPaidOutput]{}, notImplemented("billing.markPaid")
}

// MarkUncollectible is POST {basePath}/billing/markUncollectible. Writes a finalized invoice off as uncollectible; a later payment still settles it.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) MarkUncollectible(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingMarkUncollectibleInput]) (Out[apitypes.BillingMarkUncollectibleOutput], error) {
	return Out[apitypes.BillingMarkUncollectibleOutput]{}, notImplemented("billing.markUncollectible")
}

// MySpend is POST {basePath}/billing/mySpend. Reports the caller's own spend: their usage and that of the agents they sponsor, with the budgets set on them.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) MySpend(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingMySpendInput]) (Out[apitypes.BillingMySpendOutput], error) {
	return Out[apitypes.BillingMySpendOutput]{}, notImplemented("billing.mySpend")
}

// PreviewStatement is POST {basePath}/billing/previewStatement. Builds the statement a billing account would receive for a month (the current one so far by default), without issuing it.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) PreviewStatement(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingPreviewStatementInput]) (Out[apitypes.BillingPreviewStatementOutput], error) {
	return Out[apitypes.BillingPreviewStatementOutput]{}, notImplemented("billing.previewStatement")
}

// Quote is POST {basePath}/billing/quote. Prices a quantity of a meter as a month total for the tenant's billing account.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) Quote(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingQuoteInput]) (Out[apitypes.BillingQuoteOutput], error) {
	return Out[apitypes.BillingQuoteOutput]{}, notImplemented("billing.quote")
}

// Record is POST {basePath}/billing/record. Records usage of a meter in the tenant, attributed to an identity, their teams and department, with optional tags.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) Record(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingRecordInput]) (Out[apitypes.BillingRecordOutput], error) {
	return Out[apitypes.BillingRecordOutput]{}, notImplemented("billing.record")
}

// RecordMany is POST {basePath}/billing/recordMany. Records up to 100 usage events in one transaction, all or nothing.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) RecordMany(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingRecordManyInput]) (Out[apitypes.BillingRecordManyOutput], error) {
	return Out[apitypes.BillingRecordManyOutput]{}, notImplemented("billing.recordMany")
}

// RecordPayment is POST {basePath}/billing/recordPayment. Records a payment against a finalized or uncollectible invoice.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) RecordPayment(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingRecordPaymentInput]) (Out[apitypes.BillingRecordPaymentOutput], error) {
	return Out[apitypes.BillingRecordPaymentOutput]{}, notImplemented("billing.recordPayment")
}

// RedeemCoupon is POST {basePath}/billing/redeemCoupon. Redeems a coupon code for the billing account.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) RedeemCoupon(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingRedeemCouponInput]) (Out[apitypes.BillingRedeemCouponOutput], error) {
	return Out[apitypes.BillingRedeemCouponOutput]{}, notImplemented("billing.redeemCoupon")
}

// RemoveDiscount is POST {basePath}/billing/removeDiscount. Ends a billing account's discount now.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) RemoveDiscount(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingRemoveDiscountInput]) (Out[apitypes.BillingRemoveDiscountOutput], error) {
	return Out[apitypes.BillingRemoveDiscountOutput]{}, notImplemented("billing.removeDiscount")
}

// RenderInvoice is POST {basePath}/billing/renderInvoice. Returns an invoice as a standalone HTML page to print or save as PDF.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) RenderInvoice(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingRenderInvoiceInput]) (Out[apitypes.BillingRenderInvoiceOutput], error) {
	return Out[apitypes.BillingRenderInvoiceOutput]{}, notImplemented("billing.renderInvoice")
}

// ResumeSubscription is POST {basePath}/billing/resumeSubscription. Undoes a cancellation at the end of the month before it takes effect.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) ResumeSubscription(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingResumeSubscriptionInput]) (Out[apitypes.BillingResumeSubscriptionOutput], error) {
	return Out[apitypes.BillingResumeSubscriptionOutput]{}, notImplemented("billing.resumeSubscription")
}

// RevokeCredit is POST {basePath}/billing/revokeCredit. Withdraws what is left of a credit.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) RevokeCredit(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingRevokeCreditInput]) (Out[apitypes.BillingRevokeCreditOutput], error) {
	return Out[apitypes.BillingRevokeCreditOutput]{}, notImplemented("billing.revokeCredit")
}

// SetPrice is POST {basePath}/billing/setPrice. Sets or removes a rate-card price for a meter the tenant defines: its list price, or a negotiated price for a tenant below it.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) SetPrice(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingSetPriceInput]) (Out[apitypes.BillingSetPriceOutput], error) {
	return Out[apitypes.BillingSetPriceOutput]{}, notImplemented("billing.setPrice")
}

// SetProfile is POST {basePath}/billing/setProfile. Creates or updates a billing profile: company, billing emails, tax ID, address, purchase order, cost center, payment terms.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) SetProfile(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingSetProfileInput]) (Out[apitypes.BillingSetProfileOutput], error) {
	return Out[apitypes.BillingSetProfileOutput]{}, notImplemented("billing.setProfile")
}

// SetTerms is POST {basePath}/billing/setTerms. Sets a billing account's contract terms: a discount off the subtotal, a minimum monthly commitment, and the tax invoices add.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) SetTerms(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingSetTermsInput]) (Out[apitypes.BillingSetTermsOutput], error) {
	return Out[apitypes.BillingSetTermsOutput]{}, notImplemented("billing.setTerms")
}

// Spend is POST {basePath}/billing/spend. Reports the spend of the tenant and every tenant below it for a month, grouped and filtered.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) Spend(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingSpendInput]) (Out[apitypes.BillingSpendOutput], error) {
	return Out[apitypes.BillingSpendOutput]{}, notImplemented("billing.spend")
}

// Subscribe is POST {basePath}/billing/subscribe. Subscribes the billing account to a plan (id or key).
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) Subscribe(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingSubscribeInput]) (Out[apitypes.BillingSubscribeOutput], error) {
	return Out[apitypes.BillingSubscribeOutput]{}, notImplemented("billing.subscribe")
}

// TeamSpend is POST {basePath}/billing/teamSpend. Reports a team's spend, with the teams below it, grouped by identity by default.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) TeamSpend(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingTeamSpendInput]) (Out[apitypes.BillingTeamSpendOutput], error) {
	return Out[apitypes.BillingTeamSpendOutput]{}, notImplemented("billing.teamSpend")
}

// Trend is POST {basePath}/billing/trend. Returns monthly totals for the last months months (1 to 24, default 6), with the filters of spend.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) Trend(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingTrendInput]) (Out[apitypes.BillingTrendOutput], error) {
	return Out[apitypes.BillingTrendOutput]{}, notImplemented("billing.trend")
}

// UpdateBudget is POST {basePath}/billing/updateBudget. Changes a budget's name, amount, period, meters, thresholds, alerts or enforcement; its subject stays.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) UpdateBudget(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingUpdateBudgetInput]) (Out[apitypes.BillingUpdateBudgetOutput], error) {
	return Out[apitypes.BillingUpdateBudgetOutput]{}, notImplemented("billing.updateBudget")
}

// UpdateMeter is POST {basePath}/billing/updateMeter. Renames a meter, changes its unit or description, or archives it.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) UpdateMeter(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingUpdateMeterInput]) (Out[apitypes.BillingUpdateMeterOutput], error) {
	return Out[apitypes.BillingUpdateMeterOutput]{}, notImplemented("billing.updateMeter")
}

// UpdatePlan is POST {basePath}/billing/updatePlan. Changes a plan, by id or key: name, items, description, trial, self-serve, archived.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) UpdatePlan(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingUpdatePlanInput]) (Out[apitypes.BillingUpdatePlanOutput], error) {
	return Out[apitypes.BillingUpdatePlanOutput]{}, notImplemented("billing.updatePlan")
}

// UpdateSubscription is POST {basePath}/billing/updateSubscription. Changes a subscription's seats.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) UpdateSubscription(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingUpdateSubscriptionInput]) (Out[apitypes.BillingUpdateSubscriptionOutput], error) {
	return Out[apitypes.BillingUpdateSubscriptionOutput]{}, notImplemented("billing.updateSubscription")
}

// VoidStatement is POST {basePath}/billing/voidStatement. Voids a finalized statement: its credit, invoice items, coupons and advance-billed months come back and the month reopens.
//
// STUB: returns NOT_IMPLEMENTED until api/billing.ts is ported.
func (api *BillingAPI) VoidStatement(ctx context.Context, credential core.CredentialInput, input In[apitypes.BillingVoidStatementInput]) (Out[apitypes.BillingVoidStatementOutput], error) {
	return Out[apitypes.BillingVoidStatementOutput]{}, notImplemented("billing.voidStatement")
}

// IamBilling is api/billing.ts IamBilling.
type IamBilling struct {
	server *ServerContext
	// Settings The deployment's billing settings (currency, time zone, ...).
	Settings *core.Object
}

// Record (api/billing.ts IamBilling.record): Records usage without a credential and without an audit event (the hot
// path for metering).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamBilling) Record(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/billing.ts IamBilling.record")
	return
}

// RecordMany (api/billing.ts IamBilling.recordMany): Records up to 1000 events in one transaction.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamBilling) RecordMany(ctx context.Context, events []*core.Object) (result []*core.Object, err error) {
	err = notImplemented("api/billing.ts IamBilling.recordMany")
	return
}

// Check (api/billing.ts IamBilling.check): Whether usage by `identityId` in the tenant is within every enforced
// budget that covers it.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamBilling) Check(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/billing.ts IamBilling.check")
	return
}

// Spend (api/billing.ts IamBilling.spend): A spend report for a tenant's subtree.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamBilling) Spend(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/billing.ts IamBilling.spend")
	return
}

// RecordSeats (api/billing.ts IamBilling.recordSeats): Daily seat recording (scheduler job).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamBilling) RecordSeats(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/billing.ts IamBilling.recordSeats")
	return
}

// CheckBudgets (api/billing.ts IamBilling.checkBudgets): Budget threshold and forecast alerts (scheduler job).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamBilling) CheckBudgets(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/billing.ts IamBilling.checkBudgets")
	return
}

// ClosePeriod (api/billing.ts IamBilling.closePeriod): Issues statements for the previous (or a given past) period
// and sweeps old usage events (scheduler job).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamBilling) ClosePeriod(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/billing.ts IamBilling.closePeriod")
	return
}

// DetectAnomalies (api/billing.ts IamBilling.detectAnomalies): Spend-spike alerts for every billing account for
// yesterday (scheduler job, daily).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamBilling) DetectAnomalies(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/billing.ts IamBilling.detectAnomalies")
	return
}

// SendPaymentReminders (api/billing.ts IamBilling.sendPaymentReminders): Payment reminders for unpaid invoices at
// `billing.paymentReminderDays` (scheduler job, daily).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamBilling) SendPaymentReminders(ctx context.Context) (result *core.Object, err error) {
	err = notImplemented("api/billing.ts IamBilling.sendPaymentReminders")
	return
}

// RecordPayment (api/billing.ts IamBilling.recordPayment): Records a payment from a payment processor (a Stripe
// webhook, a bank feed) against an invoice by id or number. `idempotencyKey` (the processor's payment id) makes
// redelivery safe: a known key returns the invoice unchanged.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamBilling) RecordPayment(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/billing.ts IamBilling.recordPayment")
	return
}

// CreateBillingRuntime builds the IamBilling (api/billing.ts createBillingRuntime). Its methods are stubs until the module is ported.
func CreateBillingRuntime(server *ServerContext) *IamBilling {
	return &IamBilling{server: server}
}
