package server

// Skeleton of packages/server/src/api/features.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// FeaturesAPI is the `features` API group (packages/server/src/api/features.ts createFeaturesApi): every method runs through the
// operation envelope; the router maps POST {basePath}/features/{method} onto it.
type FeaturesAPI struct {
	server *ServerContext
}

// CreateFeaturesAPI builds the `features` API group.
func CreateFeaturesAPI(server *ServerContext) *FeaturesAPI {
	return &FeaturesAPI{server: server}
}

// Create is POST {basePath}/features/create. Defines a flag in the tenant: a platform flag on the root tenant, a flag for the tenant's subtree elsewhere.
//
// STUB: returns NOT_IMPLEMENTED until api/features.ts is ported.
func (api *FeaturesAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.FeaturesCreateInput]) (Out[apitypes.FeaturesCreateOutput], error) {
	return Out[apitypes.FeaturesCreateOutput]{}, notImplemented("features.create")
}

// Delete is POST {basePath}/features/delete. Deletes a flag together with every target and override set for it.
//
// STUB: returns NOT_IMPLEMENTED until api/features.ts is ported.
func (api *FeaturesAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.FeaturesDeleteInput]) (Out[apitypes.FeaturesDeleteOutput], error) {
	return Out[apitypes.FeaturesDeleteOutput]{}, notImplemented("features.delete")
}

// Evaluate is POST {basePath}/features/evaluate. Returns { tenantId, flags: { key: boolean } } for the flags that reach the tenant, for applications deciding what to show.
//
// STUB: returns NOT_IMPLEMENTED until api/features.ts is ported.
func (api *FeaturesAPI) Evaluate(ctx context.Context, credential core.CredentialInput, input In[apitypes.FeaturesEvaluateInput]) (Out[apitypes.FeaturesEvaluateOutput], error) {
	return Out[apitypes.FeaturesEvaluateOutput]{}, notImplemented("features.evaluate")
}

// List is POST {basePath}/features/list. The flags that reach the tenant, sorted by key, each with its value for the tenant and why.
//
// STUB: returns NOT_IMPLEMENTED until api/features.ts is ported.
func (api *FeaturesAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.FeaturesListInput]) (Out[apitypes.FeaturesListOutput], error) {
	return Out[apitypes.FeaturesListOutput]{}, notImplemented("features.list")
}

// ListTargets is POST {basePath}/features/listTargets. Every target and override below the defining tenant for one flag, newest first.
//
// STUB: returns NOT_IMPLEMENTED until api/features.ts is ported.
func (api *FeaturesAPI) ListTargets(ctx context.Context, credential core.CredentialInput, input In[apitypes.FeaturesListTargetsInput]) (Out[apitypes.FeaturesListTargetsOutput], error) {
	return Out[apitypes.FeaturesListTargetsOutput]{}, notImplemented("features.listTargets")
}

// SetOverride is POST {basePath}/features/setOverride. Records a tenant's own choice for a flag an ancestor defines with tenantOverridable: true.
//
// STUB: returns NOT_IMPLEMENTED until api/features.ts is ported.
func (api *FeaturesAPI) SetOverride(ctx context.Context, credential core.CredentialInput, input In[apitypes.FeaturesSetOverrideInput]) (Out[apitypes.FeaturesSetOverrideOutput], error) {
	return Out[apitypes.FeaturesSetOverrideOutput]{}, notImplemented("features.setOverride")
}

// SetTarget is POST {basePath}/features/setTarget. Pins a flag's value for a tenant below the defining tenant (tenantId), and for that tenant's descendants.
//
// STUB: returns NOT_IMPLEMENTED until api/features.ts is ported.
func (api *FeaturesAPI) SetTarget(ctx context.Context, credential core.CredentialInput, input In[apitypes.FeaturesSetTargetInput]) (Out[apitypes.FeaturesSetTargetOutput], error) {
	return Out[apitypes.FeaturesSetTargetOutput]{}, notImplemented("features.setTarget")
}

// Update is POST {basePath}/features/update. Changes a flag's settings. Fields left out keep their value.
//
// STUB: returns NOT_IMPLEMENTED until api/features.ts is ported.
func (api *FeaturesAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.FeaturesUpdateInput]) (Out[apitypes.FeaturesUpdateOutput], error) {
	return Out[apitypes.FeaturesUpdateOutput]{}, notImplemented("features.update")
}

// IamFeatures is api/features.ts IamFeatures.
type IamFeatures struct {
	server *ServerContext
}

// Evaluate (api/features.ts IamFeatures.evaluate): Every flag that reaches the tenant (internal ones included), or
// only `keys`, with values and reasons.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamFeatures) Evaluate(ctx context.Context, tenantID string, options *core.Object) (result []*core.Object, err error) {
	err = notImplemented("api/features.ts IamFeatures.evaluate")
	return
}

// Values (api/features.ts IamFeatures.values): `{ key: value }` for every flag that reaches the tenant, internal
// ones included.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamFeatures) Values(ctx context.Context, tenantID string) (result *core.Object, err error) {
	err = notImplemented("api/features.ts IamFeatures.values")
	return
}

// IsEnabled (api/features.ts IamFeatures.isEnabled): Whether one flag is on for the tenant; `false` when no flag
// with the key reaches it.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamFeatures) IsEnabled(ctx context.Context, tenantID string, key string) (result bool, err error) {
	err = notImplemented("api/features.ts IamFeatures.isEnabled")
	return
}

// CreateFeatureEvaluator builds the IamFeatures (api/features.ts createFeatureEvaluator). Its methods are stubs until the module is ported.
func CreateFeatureEvaluator(server *ServerContext) *IamFeatures {
	return &IamFeatures{server: server}
}
