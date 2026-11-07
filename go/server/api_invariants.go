package server

// Skeleton of packages/server/src/api/invariants.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// InvariantsAPI is the `invariants` API group (packages/server/src/api/invariants.ts createInvariantsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/invariants/{method} onto it.
type InvariantsAPI struct {
	server *ServerContext
}

// CreateInvariantsAPI builds the `invariants` API group.
func CreateInvariantsAPI(server *ServerContext) *InvariantsAPI {
	return &InvariantsAPI{server: server}
}

// Create is POST {basePath}/invariants/create. Stores an invariant and returns it with its current result.
//
// STUB: returns NOT_IMPLEMENTED until api/invariants.ts is ported.
func (api *InvariantsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.InvariantsCreateInput]) (Out[apitypes.InvariantsCreateOutput], error) {
	return Out[apitypes.InvariantsCreateOutput]{}, notImplemented("invariants.create")
}

// Delete is POST {basePath}/invariants/delete. Deletes an invariant, ending its monitoring and enforcement.
//
// STUB: returns NOT_IMPLEMENTED until api/invariants.ts is ported.
func (api *InvariantsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.InvariantsDeleteInput]) (Out[apitypes.InvariantsDeleteOutput], error) {
	return Out[apitypes.InvariantsDeleteOutput]{}, notImplemented("invariants.delete")
}

// List is POST {basePath}/invariants/list. Lists the tenant's invariants by name, with the outcome of the last scheduled check.
//
// STUB: returns NOT_IMPLEMENTED until api/invariants.ts is ported.
func (api *InvariantsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.InvariantsListInput]) (Out[apitypes.InvariantsListOutput], error) {
	return Out[apitypes.InvariantsListOutput]{}, notImplemented("invariants.list")
}

// Run is POST {basePath}/invariants/run. Evaluates every invariant, or one, against the current configuration and reports which pass.
//
// STUB: returns NOT_IMPLEMENTED until api/invariants.ts is ported.
func (api *InvariantsAPI) Run(ctx context.Context, credential core.CredentialInput, input In[apitypes.InvariantsRunInput]) (Out[apitypes.InvariantsRunOutput], error) {
	return Out[apitypes.InvariantsRunOutput]{}, notImplemented("invariants.run")
}

// Update is POST {basePath}/invariants/update. Changes any field of an invariant and returns it with its new result.
//
// STUB: returns NOT_IMPLEMENTED until api/invariants.ts is ported.
func (api *InvariantsAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.InvariantsUpdateInput]) (Out[apitypes.InvariantsUpdateOutput], error) {
	return Out[apitypes.InvariantsUpdateOutput]{}, notImplemented("invariants.update")
}

// SaveInvariant (api/invariants.ts saveInvariant): Creates (without `previous`) or updates an invariant after
// validating it like the API does; shared by the `invariants` API and configuration apply. `actorId` is recorded as
// the creator.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SaveInvariant(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, input *core.Object, actorID string, previous *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/invariants.ts saveInvariant")
	return
}
