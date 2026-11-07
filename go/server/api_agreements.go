package server

// Skeleton of packages/server/src/api/agreements.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// AgreementsAPI is the `agreements` API group (packages/server/src/api/agreements.ts createAgreementsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/agreements/{method} onto it.
type AgreementsAPI struct {
	server *ServerContext
}

// CreateAgreementsAPI builds the `agreements` API group.
func CreateAgreementsAPI(server *ServerContext) *AgreementsAPI {
	return &AgreementsAPI{server: server}
}

// Accept is POST {basePath}/agreements/accept. Records that you accept the given version of an agreement.
//
// STUB: returns NOT_IMPLEMENTED until api/agreements.ts is ported.
func (api *AgreementsAPI) Accept(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgreementsAcceptInput]) (Out[apitypes.AgreementsAcceptOutput], error) {
	return Out[apitypes.AgreementsAcceptOutput]{}, notImplemented("agreements.accept")
}

// Create is POST {basePath}/agreements/create. Publishes a new agreement at version 1, required by default.
//
// STUB: returns NOT_IMPLEMENTED until api/agreements.ts is ported.
func (api *AgreementsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgreementsCreateInput]) (Out[apitypes.AgreementsCreateOutput], error) {
	return Out[apitypes.AgreementsCreateOutput]{}, notImplemented("agreements.create")
}

// Delete is POST {basePath}/agreements/delete. Deletes an agreement together with every acceptance of it.
//
// STUB: returns NOT_IMPLEMENTED until api/agreements.ts is ported.
func (api *AgreementsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgreementsDeleteInput]) (Out[apitypes.AgreementsDeleteOutput], error) {
	return Out[apitypes.AgreementsDeleteOutput]{}, notImplemented("agreements.delete")
}

// List is POST {basePath}/agreements/list. Lists the tenant's agreements by name, with their full text, version, and settings.
//
// STUB: returns NOT_IMPLEMENTED until api/agreements.ts is ported.
func (api *AgreementsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgreementsListInput]) (Out[apitypes.AgreementsListOutput], error) {
	return Out[apitypes.AgreementsListOutput]{}, notImplemented("agreements.list")
}

// ListMine is POST {basePath}/agreements/listMine. Returns every agreement of the tenant with the text and whether you have accepted its current version.
//
// STUB: returns NOT_IMPLEMENTED until api/agreements.ts is ported.
func (api *AgreementsAPI) ListMine(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgreementsListMineInput]) (Out[apitypes.AgreementsListMineOutput], error) {
	return Out[apitypes.AgreementsListMineOutput]{}, notImplemented("agreements.listMine")
}

// Status is POST {basePath}/agreements/status. Reports who accepted an agreement's current version and which active people still owe it.
//
// STUB: returns NOT_IMPLEMENTED until api/agreements.ts is ported.
func (api *AgreementsAPI) Status(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgreementsStatusInput]) (Out[apitypes.AgreementsStatusOutput], error) {
	return Out[apitypes.AgreementsStatusOutput]{}, notImplemented("agreements.status")
}

// Update is POST {basePath}/agreements/update. Edits an agreement, optionally publishing the change as a new version that everyone must accept again.
//
// STUB: returns NOT_IMPLEMENTED until api/agreements.ts is ported.
func (api *AgreementsAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgreementsUpdateInput]) (Out[apitypes.AgreementsUpdateOutput], error) {
	return Out[apitypes.AgreementsUpdateOutput]{}, notImplemented("agreements.update")
}

// DeleteAgreement (api/agreements.ts deleteAgreement): Deletes an agreement with every acceptance of it.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DeleteAgreement(ctx context.Context, tx core.IamStore, agreement *core.Object) (err error) {
	err = notImplemented("api/agreements.ts deleteAgreement")
	return
}

// SaveAgreement (api/agreements.ts saveAgreement): Publishes (without `previous`) or edits an agreement after
// validating it; `newVersion` asks everyone to accept again. Shared by the `agreements` API and configuration apply.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SaveAgreement(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, input *core.Object, previous *core.Object, newVersion bool) (result *core.Object, err error) {
	err = notImplemented("api/agreements.ts saveAgreement")
	return
}
