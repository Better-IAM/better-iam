package server

// Skeleton of packages/server/src/api/resources.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// ResourcesAPI is the `resources` API group (packages/server/src/api/resources.ts createResourcesApi): every method runs through the
// operation envelope; the router maps POST {basePath}/resources/{method} onto it.
type ResourcesAPI struct {
	server *ServerContext
}

// CreateResourcesAPI builds the `resources` API group.
func CreateResourcesAPI(server *ServerContext) *ResourcesAPI {
	return &ResourcesAPI{server: server}
}

// Delete is POST {basePath}/resources/delete. Removes a registered resource and every relationship tuple on it.
//
// STUB: returns NOT_IMPLEMENTED until api/resources.ts is ported.
func (api *ResourcesAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.ResourcesDeleteInput]) (Out[apitypes.ResourcesDeleteOutput], error) {
	return Out[apitypes.ResourcesDeleteOutput]{}, notImplemented("resources.delete")
}

// Get is POST {basePath}/resources/get. Returns the registration of one resource.
//
// STUB: returns NOT_IMPLEMENTED until api/resources.ts is ported.
func (api *ResourcesAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.ResourcesGetInput]) (Out[apitypes.ResourcesGetOutput], error) {
	return Out[apitypes.ResourcesGetOutput]{}, notImplemented("resources.get")
}

// List is POST {basePath}/resources/list. Lists registered resources, optionally of one type, under one parent, or owned by one identity.
//
// STUB: returns NOT_IMPLEMENTED until api/resources.ts is ported.
func (api *ResourcesAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.ResourcesListInput]) (Out[apitypes.ResourcesListOutput], error) {
	return Out[apitypes.ResourcesListOutput]{}, notImplemented("resources.list")
}

// Register is POST {basePath}/resources/register. Registers a managed resource with its attributes, owner, and parent.
//
// STUB: returns NOT_IMPLEMENTED until api/resources.ts is ported.
func (api *ResourcesAPI) Register(ctx context.Context, credential core.CredentialInput, input In[apitypes.ResourcesRegisterInput]) (Out[apitypes.ResourcesRegisterOutput], error) {
	return Out[apitypes.ResourcesRegisterOutput]{}, notImplemented("resources.register")
}

// RegisterMany is POST {basePath}/resources/registerMany. Registers up to 100 managed resources in one transaction, either all of them or none.
//
// STUB: returns NOT_IMPLEMENTED until api/resources.ts is ported.
func (api *ResourcesAPI) RegisterMany(ctx context.Context, credential core.CredentialInput, input In[apitypes.ResourcesRegisterManyInput]) (Out[apitypes.ResourcesRegisterManyOutput], error) {
	return Out[apitypes.ResourcesRegisterManyOutput]{}, notImplemented("resources.registerMany")
}

// Update is POST {basePath}/resources/update. Replaces a registered resource's attributes, or changes or clears its owner.
//
// STUB: returns NOT_IMPLEMENTED until api/resources.ts is ported.
func (api *ResourcesAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.ResourcesUpdateInput]) (Out[apitypes.ResourcesUpdateOutput], error) {
	return Out[apitypes.ResourcesUpdateOutput]{}, notImplemented("resources.update")
}
