package server

// Skeleton of packages/server/src/billing-service.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// BillingService is billing-service.ts billingServiceOf().
type BillingService struct {
	server   *ServerContext
	Settings *core.Object
	Hooks    *BillingHooks
}

// CurrentPeriod (billing-service.ts billingServiceOf().currentPeriod): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) CurrentPeriod() (result string, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().currentPeriod")
	return
}

// Record (billing-service.ts billingServiceOf().record): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) Record(ctx context.Context, tx core.IamStore, input *core.Object, recordedBy string, extra *core.Object) (result *core.Object, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().record")
	return
}

// Report (billing-service.ts billingServiceOf().report): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) Report(ctx context.Context, tx core.IamStore, scope *core.Object, query *core.Object, cache map[string]any, rowFilter func(*core.Object) bool) (result *core.Object, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().report")
	return
}

// Trend (billing-service.ts billingServiceOf().trend): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) Trend(ctx context.Context, tx core.IamStore, scope *core.Object, input *core.Object, rowFilter func(*core.Object) bool) (result *core.Object, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().trend")
	return
}

// Check (billing-service.ts billingServiceOf().check): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) Check(ctx context.Context, tx core.IamStore, tenant *core.Object, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().check")
	return
}

// SpendContext (billing-service.ts billingServiceOf().spendContext): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) SpendContext(ctx context.Context, tx core.IamStore, tenant *core.Object, identityID string) (result *core.Object, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().spendContext")
	return
}

// BudgetStatus (billing-service.ts billingServiceOf().budgetStatus): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) BudgetStatus(ctx context.Context, tx core.IamStore, budget *core.Object, cache map[string]any) (result *core.Object, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().budgetStatus")
	return
}

// CheckBudgets (billing-service.ts billingServiceOf().checkBudgets): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) CheckBudgets(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().checkBudgets")
	return
}

// DraftStatement (billing-service.ts billingServiceOf().draftStatement): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) DraftStatement(ctx context.Context, tx core.IamStore, account *core.Object, period string, cache map[string]any, first *core.Object) (result *core.Object, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().draftStatement")
	return
}

// StatementFor (billing-service.ts billingServiceOf().statementFor): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) StatementFor(ctx context.Context, tx core.IamStore, accountID string, period string) (result *core.Object, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().statementFor")
	return
}

// ClosePeriod (billing-service.ts billingServiceOf().closePeriod): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) ClosePeriod(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().closePeriod")
	return
}

// FinalizeDraft (billing-service.ts billingServiceOf().finalizeDraft): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) FinalizeDraft(ctx context.Context, tx core.IamStore, statement *core.Object, actorID string) (result *core.Object, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().finalizeDraft")
	return
}

// VoidStatement (billing-service.ts billingServiceOf().voidStatement): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) VoidStatement(ctx context.Context, tx core.IamStore, statement *core.Object, principal *Principal, reason string) (result *core.Object, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().voidStatement")
	return
}

// RecordPayment (billing-service.ts billingServiceOf().recordPayment): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) RecordPayment(ctx context.Context, tx core.IamStore, statement *core.Object, input *core.Object, actorID string) (result *core.Object, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().recordPayment")
	return
}

// MarkUncollectible (billing-service.ts billingServiceOf().markUncollectible): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) MarkUncollectible(ctx context.Context, tx core.IamStore, statement *core.Object) (result *core.Object, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().markUncollectible")
	return
}

// CreateCreditNote (billing-service.ts billingServiceOf().createCreditNote): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) CreateCreditNote(ctx context.Context, tx core.IamStore, statement *core.Object, input *core.Object, actorID string) (result *core.Object, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().createCreditNote")
	return
}

// SendPaymentReminders (billing-service.ts billingServiceOf().sendPaymentReminders): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) SendPaymentReminders(ctx context.Context) (result *core.Object, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().sendPaymentReminders")
	return
}

// Subscribe (billing-service.ts billingServiceOf().subscribe): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) Subscribe(ctx context.Context, tx core.IamStore, account *core.Object, plan *core.Object, input *core.Object, actorID string) (result *core.Object, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().subscribe")
	return
}

// UpdateSeats (billing-service.ts billingServiceOf().updateSeats): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) UpdateSeats(ctx context.Context, tx core.IamStore, subscription *core.Object, seats float64, actorID string) (result *core.Object, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().updateSeats")
	return
}

// CancelSubscription (billing-service.ts billingServiceOf().cancelSubscription): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) CancelSubscription(ctx context.Context, tx core.IamStore, subscription *core.Object, atPeriodEnd bool, actorID string) (result *core.Object, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().cancelSubscription")
	return
}

// ResumeSubscription (billing-service.ts billingServiceOf().resumeSubscription): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) ResumeSubscription(ctx context.Context, tx core.IamStore, subscription *core.Object) (result *core.Object, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().resumeSubscription")
	return
}

// ChangePlan (billing-service.ts billingServiceOf().changePlan): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) ChangePlan(ctx context.Context, tx core.IamStore, subscription *core.Object, plan *core.Object, actorID string) (result *core.Object, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().changePlan")
	return
}

// RecordSeats (billing-service.ts billingServiceOf().recordSeats): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) RecordSeats(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().recordSeats")
	return
}

// OwnIdentities (billing-service.ts billingServiceOf().ownIdentities): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) OwnIdentities(ctx context.Context, tx core.IamStore, identity *core.Object) (result []string, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().ownIdentities")
	return
}

// TeamWithin (billing-service.ts billingServiceOf().teamWithin): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) TeamWithin(dir *core.Object, candidate string, teamID string) (result bool, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().teamWithin")
	return
}

// DepartmentWithin (billing-service.ts billingServiceOf().departmentWithin): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) DepartmentWithin(dir *core.Object, candidate string, departmentID string) (result bool, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().departmentWithin")
	return
}

// Anomalies (billing-service.ts billingServiceOf().anomalies): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) Anomalies(ctx context.Context, tx core.IamStore, scope *core.Object, input *core.Object) (result []*core.Object, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().anomalies")
	return
}

// DetectAnomalies (billing-service.ts billingServiceOf().detectAnomalies): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) DetectAnomalies(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().detectAnomalies")
	return
}

// SpendCsv (billing-service.ts billingServiceOf().spendCsv): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) SpendCsv(report *core.Object) (result string, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().spendCsv")
	return
}

// StatementCsv (billing-service.ts billingServiceOf().statementCsv): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingService) StatementCsv(statement *core.Object) (result string, err error) {
	err = notImplemented("billing-service.ts billingServiceOf().statementCsv")
	return
}

// BillingServiceOf builds the BillingService (billing-service.ts billingServiceOf). Its methods are stubs until the module is ported.
func BillingServiceOf(server *ServerContext) *BillingService {
	return &BillingService{server: server}
}

// BuiltInMeterKey (billing-service.ts builtInMeterKey): Whether a key names a built-in meter: only the platform (the
// root tenant) defines those.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func BuiltInMeterKey(key string) (result bool, err error) {
	err = notImplemented("billing-service.ts builtInMeterKey")
	return
}

// MentionsSpend (billing-service.ts mentionsSpend): whether any statement of the documents names a spend context
// key, so decisions read budgets only when needed.
func MentionsSpend(documents []any) bool {
	return anyStatementsMention(documents, "principal.spendExceeded") || anyStatementsMention(documents, "principal.budgetsExceeded")
}

// BillingHooks is billing-service.ts BillingHooks.
type BillingHooks struct {
	server *ServerContext
}

// RecordPriced (billing-service.ts BillingHooks.recordPriced): Records already-priced usage in the caller's
// transaction. Never throws: billing problems must not fail the work being billed. A meter the tenant does not have
// yet is defined on the root tenant for the built-in keys (`inference`); other unknown meters are skipped.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *BillingHooks) RecordPriced(ctx context.Context, tx core.IamStore, input *core.Object) (err error) {
	err = notImplemented("billing-service.ts BillingHooks.recordPriced")
	return
}
