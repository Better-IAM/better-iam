package server

// Skeleton of packages/server/src/api/certifications.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// CertificationsAPI is the `certifications` API group (packages/server/src/api/certifications.ts createCertificationsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/certifications/{method} onto it.
type CertificationsAPI struct {
	server *ServerContext
}

// CreateCertificationsAPI builds the `certifications` API group.
func CreateCertificationsAPI(server *ServerContext) *CertificationsAPI {
	return &CertificationsAPI{server: server}
}

// Close is POST {basePath}/certifications/close. Closes an open campaign and applies it, removing the bindings reviewers revoked.
//
// STUB: returns NOT_IMPLEMENTED until api/certifications.ts is ported.
func (api *CertificationsAPI) Close(ctx context.Context, credential core.CredentialInput, input In[apitypes.CertificationsCloseInput]) (Out[apitypes.CertificationsCloseOutput], error) {
	return Out[apitypes.CertificationsCloseOutput]{}, notImplemented("certifications.close")
}

// Create is POST {basePath}/certifications/create. Opens a campaign over the tenant's current role bindings and notifies the reviewers.
//
// STUB: returns NOT_IMPLEMENTED until api/certifications.ts is ported.
func (api *CertificationsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.CertificationsCreateInput]) (Out[apitypes.CertificationsCreateOutput], error) {
	return Out[apitypes.CertificationsCreateOutput]{}, notImplemented("certifications.create")
}

// Decide is POST {basePath}/certifications/decide. Records keep or revoke decisions on up to 200 items of an open campaign.
//
// STUB: returns NOT_IMPLEMENTED until api/certifications.ts is ported.
func (api *CertificationsAPI) Decide(ctx context.Context, credential core.CredentialInput, input In[apitypes.CertificationsDecideInput]) (Out[apitypes.CertificationsDecideOutput], error) {
	return Out[apitypes.CertificationsDecideOutput]{}, notImplemented("certifications.decide")
}

// Delete is POST {basePath}/certifications/delete. Deletes a closed campaign and all its items.
//
// STUB: returns NOT_IMPLEMENTED until api/certifications.ts is ported.
func (api *CertificationsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.CertificationsDeleteInput]) (Out[apitypes.CertificationsDeleteOutput], error) {
	return Out[apitypes.CertificationsDeleteOutput]{}, notImplemented("certifications.delete")
}

// Get is POST {basePath}/certifications/get. Returns one campaign with its items and progress.
//
// STUB: returns NOT_IMPLEMENTED until api/certifications.ts is ported.
func (api *CertificationsAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.CertificationsGetInput]) (Out[apitypes.CertificationsGetOutput], error) {
	return Out[apitypes.CertificationsGetOutput]{}, notImplemented("certifications.get")
}

// List is POST {basePath}/certifications/list. Lists the tenant's campaigns, newest first, each with its progress.
//
// STUB: returns NOT_IMPLEMENTED until api/certifications.ts is ported.
func (api *CertificationsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.CertificationsListInput]) (Out[apitypes.CertificationsListOutput], error) {
	return Out[apitypes.CertificationsListOutput]{}, notImplemented("certifications.list")
}

// ListMine is POST {basePath}/certifications/listMine. Lists the open campaigns that have items assigned to you as a manager, with only those items.
//
// STUB: returns NOT_IMPLEMENTED until api/certifications.ts is ported.
func (api *CertificationsAPI) ListMine(ctx context.Context, credential core.CredentialInput, input In[apitypes.CertificationsListMineInput]) (Out[apitypes.CertificationsListMineOutput], error) {
	return Out[apitypes.CertificationsListMineOutput]{}, notImplemented("certifications.listMine")
}

// Remind is POST {basePath}/certifications/remind. Emails every reviewer who still has undecided items a reminder with their pending count.
//
// STUB: returns NOT_IMPLEMENTED until api/certifications.ts is ported.
func (api *CertificationsAPI) Remind(ctx context.Context, credential core.CredentialInput, input In[apitypes.CertificationsRemindInput]) (Out[apitypes.CertificationsRemindOutput], error) {
	return Out[apitypes.CertificationsRemindOutput]{}, notImplemented("certifications.remind")
}

// Review is POST {basePath}/certifications/review. Records a manager's keep or revoke decisions on up to 200 items assigned to them, without a certification permission.
//
// STUB: returns NOT_IMPLEMENTED until api/certifications.ts is ported.
func (api *CertificationsAPI) Review(ctx context.Context, credential core.CredentialInput, input In[apitypes.CertificationsReviewInput]) (Out[apitypes.CertificationsReviewOutput], error) {
	return Out[apitypes.CertificationsReviewOutput]{}, notImplemented("certifications.review")
}

// ApplyCampaign (api/certifications.ts applyCampaign): Applies an open campaign and closes it inside the caller's
// transaction: revoked (and, with `undecided: 'revoke'`, undecided) bindings are removed under the principal's grant
// authority, and each item records its outcome. Bindings the principal may not remove are reported as
// `revocation-failed`; without a principal (the creator of an auto-closing campaign no longer exists) every
// revocation is.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ApplyCampaign(ctx context.Context, server *ServerContext, tx core.IamStore, campaign *core.Object, principal *Principal, options *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/certifications.ts applyCampaign")
	return
}
