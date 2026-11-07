package server

// Skeleton of packages/server/src/api/privacy.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// PrivacyAPI is the `privacy` API group (packages/server/src/api/privacy.ts createPrivacyApi): every method runs through the
// operation envelope; the router maps POST {basePath}/privacy/{method} onto it.
type PrivacyAPI struct {
	server *ServerContext
}

// CreatePrivacyAPI builds the `privacy` API group.
func CreatePrivacyAPI(server *ServerContext) *PrivacyAPI {
	return &PrivacyAPI{server: server}
}

// AddNote is POST {basePath}/privacy/addNote. Adds an internal note to a request's timeline.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) AddNote(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyAddNoteInput]) (Out[apitypes.PrivacyAddNoteOutput], error) {
	return Out[apitypes.PrivacyAddNoteOutput]{}, notImplemented("privacy.addNote")
}

// AssignRequest is POST {basePath}/privacy/assignRequest. Hands a request to a handler, or clears the assignment with assigneeId: null.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) AssignRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyAssignRequestInput]) (Out[apitypes.PrivacyAssignRequestOutput], error) {
	return Out[apitypes.PrivacyAssignRequestOutput]{}, notImplemented("privacy.assignRequest")
}

// Audience is POST {basePath}/privacy/audience. Lists the subjects a purpose may be processed for right now.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) Audience(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyAudienceInput]) (Out[apitypes.PrivacyAudienceOutput], error) {
	return Out[apitypes.PrivacyAudienceOutput]{}, notImplemented("privacy.audience")
}

// CancelMyRequest is POST {basePath}/privacy/cancelMyRequest. Withdraws one of your own requests while it is still being handled.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) CancelMyRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyCancelMyRequestInput]) (Out[apitypes.PrivacyCancelMyRequestOutput], error) {
	return Out[apitypes.PrivacyCancelMyRequestOutput]{}, notImplemented("privacy.cancelMyRequest")
}

// Check is POST {basePath}/privacy/check. Tells whether a purpose may be processed for one subject right now, and why.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) Check(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyCheckInput]) (Out[apitypes.PrivacyCheckOutput], error) {
	return Out[apitypes.PrivacyCheckOutput]{}, notImplemented("privacy.check")
}

// ConfirmPublic is POST {basePath}/privacy/confirmPublic (public: no request credential). Confirms a public request from the link emailed to the requester.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) ConfirmPublic(ctx context.Context, input In[apitypes.PrivacyConfirmPublicInput]) (Out[apitypes.PrivacyConfirmPublicOutput], error) {
	return Out[apitypes.PrivacyConfirmPublicOutput]{}, notImplemented("privacy.confirmPublic")
}

// CreatePurpose is POST {basePath}/privacy/createPurpose. Adds a processing purpose at version 1.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) CreatePurpose(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyCreatePurposeInput]) (Out[apitypes.PrivacyCreatePurposeOutput], error) {
	return Out[apitypes.PrivacyCreatePurposeOutput]{}, notImplemented("privacy.createPurpose")
}

// CreateRequest is POST {basePath}/privacy/createRequest. Files a data-subject request on someone's behalf, received by phone, mail or a support ticket.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) CreateRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyCreateRequestInput]) (Out[apitypes.PrivacyCreateRequestOutput], error) {
	return Out[apitypes.PrivacyCreateRequestOutput]{}, notImplemented("privacy.createRequest")
}

// Decide is POST {basePath}/privacy/decide. Records your own decision on a purpose and returns its signed receipt.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) Decide(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyDecideInput]) (Out[apitypes.PrivacyDecideOutput], error) {
	return Out[apitypes.PrivacyDecideOutput]{}, notImplemented("privacy.decide")
}

// DeletePurpose is POST {basePath}/privacy/deletePurpose. Deletes a purpose nobody has decided on yet.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) DeletePurpose(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyDeletePurposeInput]) (Out[apitypes.PrivacyDeletePurposeOutput], error) {
	return Out[apitypes.PrivacyDeletePurposeOutput]{}, notImplemented("privacy.deletePurpose")
}

// DownloadExport is POST {basePath}/privacy/downloadExport. Returns the export an access or portability request produced.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) DownloadExport(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyDownloadExportInput]) (Out[apitypes.PrivacyDownloadExportOutput], error) {
	return Out[apitypes.PrivacyDownloadExportOutput]{}, notImplemented("privacy.downloadExport")
}

// ExtendRequest is POST {basePath}/privacy/extendRequest. Extends an open request's deadline once by the regulation's extension, telling the subject why.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) ExtendRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyExtendRequestInput]) (Out[apitypes.PrivacyExtendRequestOutput], error) {
	return Out[apitypes.PrivacyExtendRequestOutput]{}, notImplemented("privacy.extendRequest")
}

// FilterSubjects is POST {basePath}/privacy/filterSubjects. Splits up to 1000 subjects into those a purpose may be processed for and those it may not.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) FilterSubjects(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyFilterSubjectsInput]) (Out[apitypes.PrivacyFilterSubjectsOutput], error) {
	return Out[apitypes.PrivacyFilterSubjectsOutput]{}, notImplemented("privacy.filterSubjects")
}

// FulfilRequest is POST {basePath}/privacy/fulfilRequest. Completes an open request by doing what it asks, and emails the subject.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) FulfilRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyFulfilRequestInput]) (Out[apitypes.PrivacyFulfilRequestOutput], error) {
	return Out[apitypes.PrivacyFulfilRequestOutput]{}, notImplemented("privacy.fulfilRequest")
}

// GetRequest is POST {basePath}/privacy/getRequest. Returns one request with the subject's legal hold and restriction status.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) GetRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyGetRequestInput]) (Out[apitypes.PrivacyGetRequestOutput], error) {
	return Out[apitypes.PrivacyGetRequestOutput]{}, notImplemented("privacy.getRequest")
}

// GetSettings is POST {basePath}/privacy/getSettings. Returns the tenant's privacy settings with the statutory windows.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) GetSettings(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyGetSettingsInput]) (Out[apitypes.PrivacyGetSettingsOutput], error) {
	return Out[apitypes.PrivacyGetSettingsOutput]{}, notImplemented("privacy.getSettings")
}

// History is POST {basePath}/privacy/history. Lists a subject's recorded decisions, newest first.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) History(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyHistoryInput]) (Out[apitypes.PrivacyHistoryOutput], error) {
	return Out[apitypes.PrivacyHistoryOutput]{}, notImplemented("privacy.history")
}

// ImportDecisions is POST {basePath}/privacy/importDecisions. Imports up to 500 consent decisions from another system in one transaction.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) ImportDecisions(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyImportDecisionsInput]) (Out[apitypes.PrivacyImportDecisionsOutput], error) {
	return Out[apitypes.PrivacyImportDecisionsOutput]{}, notImplemented("privacy.importDecisions")
}

// LiftRestriction is POST {basePath}/privacy/liftRestriction. Ends a restriction of processing for a subject.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) LiftRestriction(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyLiftRestrictionInput]) (Out[apitypes.PrivacyLiftRestrictionOutput], error) {
	return Out[apitypes.PrivacyLiftRestrictionOutput]{}, notImplemented("privacy.liftRestriction")
}

// LinkRequest is POST {basePath}/privacy/linkRequest. Links a request known only by an email address to the account or application subject it is about.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) LinkRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyLinkRequestInput]) (Out[apitypes.PrivacyLinkRequestOutput], error) {
	return Out[apitypes.PrivacyLinkRequestOutput]{}, notImplemented("privacy.linkRequest")
}

// ListConsents is POST {basePath}/privacy/listConsents. Lists current decisions, newest first, each with its state.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) ListConsents(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyListConsentsInput]) (Out[apitypes.PrivacyListConsentsOutput], error) {
	return Out[apitypes.PrivacyListConsentsOutput]{}, notImplemented("privacy.listConsents")
}

// ListHolds is POST {basePath}/privacy/listHolds. Lists the tenant's legal holds, newest first.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) ListHolds(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyListHoldsInput]) (Out[apitypes.PrivacyListHoldsOutput], error) {
	return Out[apitypes.PrivacyListHoldsOutput]{}, notImplemented("privacy.listHolds")
}

// ListPurposes is POST {basePath}/privacy/listPurposes. Lists the tenant's purposes by name.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) ListPurposes(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyListPurposesInput]) (Out[apitypes.PrivacyListPurposesOutput], error) {
	return Out[apitypes.PrivacyListPurposesOutput]{}, notImplemented("privacy.listPurposes")
}

// ListRequests is POST {basePath}/privacy/listRequests. Lists requests, open ones first by deadline, then the newest.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) ListRequests(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyListRequestsInput]) (Out[apitypes.PrivacyListRequestsOutput], error) {
	return Out[apitypes.PrivacyListRequestsOutput]{}, notImplemented("privacy.listRequests")
}

// ListRestrictions is POST {basePath}/privacy/listRestrictions. Lists subjects whose processing is restricted, newest first.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) ListRestrictions(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyListRestrictionsInput]) (Out[apitypes.PrivacyListRestrictionsOutput], error) {
	return Out[apitypes.PrivacyListRestrictionsOutput]{}, notImplemented("privacy.listRestrictions")
}

// Mine is POST {basePath}/privacy/mine. Returns your privacy page: every purpose with your decision and its effect, your requests, and the privacy contact.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) Mine(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyMineInput]) (Out[apitypes.PrivacyMineOutput], error) {
	return Out[apitypes.PrivacyMineOutput]{}, notImplemented("privacy.mine")
}

// MyHistory is POST {basePath}/privacy/myHistory. Lists your own recorded decisions, newest first.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) MyHistory(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyMyHistoryInput]) (Out[apitypes.PrivacyMyHistoryOutput], error) {
	return Out[apitypes.PrivacyMyHistoryOutput]{}, notImplemented("privacy.myHistory")
}

// MyReceipt is POST {basePath}/privacy/myReceipt. Returns the signed receipt of one of your own decisions.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) MyReceipt(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyMyReceiptInput]) (Out[apitypes.PrivacyMyReceiptOutput], error) {
	return Out[apitypes.PrivacyMyReceiptOutput]{}, notImplemented("privacy.myReceipt")
}

// PlaceHold is POST {basePath}/privacy/placeHold. Places a legal hold on a subject: erasure, and every deletion of their account, is refused until it is released.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) PlaceHold(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyPlaceHoldInput]) (Out[apitypes.PrivacyPlaceHoldOutput], error) {
	return Out[apitypes.PrivacyPlaceHoldOutput]{}, notImplemented("privacy.placeHold")
}

// Record is POST {basePath}/privacy/record. Records a consent decision for a person of the tenant or an application subject, and returns its receipt.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) Record(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyRecordInput]) (Out[apitypes.PrivacyRecordOutput], error) {
	return Out[apitypes.PrivacyRecordOutput]{}, notImplemented("privacy.record")
}

// RejectRequest is POST {basePath}/privacy/rejectRequest. Declines an open or unverified request with a reason the subject is emailed.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) RejectRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyRejectRequestInput]) (Out[apitypes.PrivacyRejectRequestOutput], error) {
	return Out[apitypes.PrivacyRejectRequestOutput]{}, notImplemented("privacy.rejectRequest")
}

// ReleaseHold is POST {basePath}/privacy/releaseHold. Releases a legal hold.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) ReleaseHold(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyReleaseHoldInput]) (Out[apitypes.PrivacyReleaseHoldOutput], error) {
	return Out[apitypes.PrivacyReleaseHoldOutput]{}, notImplemented("privacy.releaseHold")
}

// SubmitPublic is POST {basePath}/privacy/submitPublic (public: no request credential). Files a request from someone without an account, from a public form, when the organization turned on public intake.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) SubmitPublic(ctx context.Context, input In[apitypes.PrivacySubmitPublicInput]) (Out[apitypes.PrivacySubmitPublicOutput], error) {
	return Out[apitypes.PrivacySubmitPublicOutput]{}, notImplemented("privacy.submitPublic")
}

// SubmitRequest is POST {basePath}/privacy/submitRequest. Files a data-subject request for yourself; signing in verified who you are, so its deadline starts at once.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) SubmitRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacySubmitRequestInput]) (Out[apitypes.PrivacySubmitRequestOutput], error) {
	return Out[apitypes.PrivacySubmitRequestOutput]{}, notImplemented("privacy.submitRequest")
}

// Summary is POST {basePath}/privacy/summary. Returns consent counts per purpose, the request queue, holds and restrictions at a glance.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) Summary(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacySummaryInput]) (Out[apitypes.PrivacySummaryOutput], error) {
	return Out[apitypes.PrivacySummaryOutput]{}, notImplemented("privacy.summary")
}

// UpdatePurpose is POST {basePath}/privacy/updatePurpose. Edits a purpose, optionally publishing the change as a new version or archiving it.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) UpdatePurpose(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyUpdatePurposeInput]) (Out[apitypes.PrivacyUpdatePurposeOutput], error) {
	return Out[apitypes.PrivacyUpdatePurposeOutput]{}, notImplemented("privacy.updatePurpose")
}

// UpdateSettings is POST {basePath}/privacy/updateSettings. Changes the privacy contact, default regulation, internal response windows, public intake and export lifetime.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) UpdateSettings(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyUpdateSettingsInput]) (Out[apitypes.PrivacyUpdateSettingsOutput], error) {
	return Out[apitypes.PrivacyUpdateSettingsOutput]{}, notImplemented("privacy.updateSettings")
}

// VerifyReceipt is POST {basePath}/privacy/verifyReceipt. Checks a consent receipt someone presents against the signature and the history.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) VerifyReceipt(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyVerifyReceiptInput]) (Out[apitypes.PrivacyVerifyReceiptOutput], error) {
	return Out[apitypes.PrivacyVerifyReceiptOutput]{}, notImplemented("privacy.verifyReceipt")
}

// VerifyRequest is POST {basePath}/privacy/verifyRequest. Records how the requester's identity was confirmed, which opens the request and starts its deadline.
//
// STUB: returns NOT_IMPLEMENTED until api/privacy.ts is ported.
func (api *PrivacyAPI) VerifyRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyVerifyRequestInput]) (Out[apitypes.PrivacyVerifyRequestOutput], error) {
	return Out[apitypes.PrivacyVerifyRequestOutput]{}, notImplemented("privacy.verifyRequest")
}

// PrivacyRuntime is api/privacy.ts createPrivacyRuntime().
type PrivacyRuntime struct {
	server *ServerContext
}

// Check (api/privacy.ts createPrivacyRuntime().check): Whether a purpose may be processed for a subject right now;
// not audited.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *PrivacyRuntime) Check(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/privacy.ts createPrivacyRuntime().check")
	return
}

// Record (api/privacy.ts createPrivacyRuntime().record): Records a decision the application captured itself (a
// cookie banner, a signup form), attributed to `application`. Audited as `privacy:consent`; returns the receipt.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *PrivacyRuntime) Record(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/privacy.ts createPrivacyRuntime().record")
	return
}

// SendDeadlineReminders (api/privacy.ts createPrivacyRuntime().sendDeadlineReminders): Deadline job (daily or
// hourly): emails the assignee (or the privacy contact) once when an open request is due within `withinDays`
// (default 7) and once when it becomes overdue, audited as `privacy:request:due-soon` / `privacy:request:overdue` so
// webhooks can alert too; cancels public requests nobody confirmed within seven days.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *PrivacyRuntime) SendDeadlineReminders(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/privacy.ts createPrivacyRuntime().sendDeadlineReminders")
	return
}

// CreatePrivacyRuntime builds the PrivacyRuntime (api/privacy.ts createPrivacyRuntime). Its methods are stubs until the module is ported.
func CreatePrivacyRuntime(server *ServerContext) *PrivacyRuntime {
	return &PrivacyRuntime{server: server}
}
