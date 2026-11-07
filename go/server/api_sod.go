package server

// Skeleton of packages/server/src/api/sod.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// SodAPI is the `sod` API group (packages/server/src/api/sod.ts createSodApi): every method runs through the
// operation envelope; the router maps POST {basePath}/sod/{method} onto it.
type SodAPI struct {
	server *ServerContext
}

// CreateSodAPI builds the `sod` API group.
func CreateSodAPI(server *ServerContext) *SodAPI {
	return &SodAPI{server: server}
}

// Create is POST {basePath}/sod/create. Declares 2 to 20 roles that nobody may hold together, and reports how many people already hold two of them.
//
// STUB: returns NOT_IMPLEMENTED until api/sod.ts is ported.
func (api *SodAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.SodCreateInput]) (Out[apitypes.SodCreateOutput], error) {
	return Out[apitypes.SodCreateOutput]{}, notImplemented("sod.create")
}

// Delete is POST {basePath}/sod/delete. Removes a rule, so the combination is no longer checked or reported.
//
// STUB: returns NOT_IMPLEMENTED until api/sod.ts is ported.
func (api *SodAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.SodDeleteInput]) (Out[apitypes.SodDeleteOutput], error) {
	return Out[apitypes.SodDeleteOutput]{}, notImplemented("sod.delete")
}

// List is POST {basePath}/sod/list. Lists the tenant's rules, newest first.
//
// STUB: returns NOT_IMPLEMENTED until api/sod.ts is ported.
func (api *SodAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.SodListInput]) (Out[apitypes.SodListOutput], error) {
	return Out[apitypes.SodListOutput]{}, notImplemented("sod.list")
}

// Update is POST {basePath}/sod/update. Changes a rule's name, description, roles, or mode.
//
// STUB: returns NOT_IMPLEMENTED until api/sod.ts is ported.
func (api *SodAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.SodUpdateInput]) (Out[apitypes.SodUpdateOutput], error) {
	return Out[apitypes.SodUpdateOutput]{}, notImplemented("sod.update")
}

// Violations is POST {basePath}/sod/violations. Lists everyone who currently holds two or more roles of a rule, with names for review screens.
//
// STUB: returns NOT_IMPLEMENTED until api/sod.ts is ported.
func (api *SodAPI) Violations(ctx context.Context, credential core.CredentialInput, input In[apitypes.SodViolationsInput]) (Out[apitypes.SodViolationsOutput], error) {
	return Out[apitypes.SodViolationsOutput]{}, notImplemented("sod.violations")
}
