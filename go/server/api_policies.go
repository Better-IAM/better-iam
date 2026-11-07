package server

// Skeleton of packages/server/src/api/policies.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// PoliciesAPI is the `policies` API group (packages/server/src/api/policies.ts createPoliciesApi): every method runs through the
// operation envelope; the router maps POST {basePath}/policies/{method} onto it.
type PoliciesAPI struct {
	server *ServerContext
}

// CreatePoliciesAPI builds the `policies` API group.
func CreatePoliciesAPI(server *ServerContext) *PoliciesAPI {
	return &PoliciesAPI{server: server}
}

// Create is POST {basePath}/policies/create. Stores a new policy document at version 1 under your grant authority.
//
// STUB: returns NOT_IMPLEMENTED until api/policies.ts is ported.
func (api *PoliciesAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.PoliciesCreateInput]) (Out[apitypes.PoliciesCreateOutput], error) {
	return Out[apitypes.PoliciesCreateOutput]{}, notImplemented("policies.create")
}

// Delete is POST {basePath}/policies/delete. Deletes a policy that no role attaches.
//
// STUB: returns NOT_IMPLEMENTED until api/policies.ts is ported.
func (api *PoliciesAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.PoliciesDeleteInput]) (Out[apitypes.PoliciesDeleteOutput], error) {
	return Out[apitypes.PoliciesDeleteOutput]{}, notImplemented("policies.delete")
}

// EffectiveActions is POST {basePath}/policies/effectiveActions. Lists which actions one identity could perform on one resource, with a reason per action.
//
// STUB: returns NOT_IMPLEMENTED until api/policies.ts is ported.
func (api *PoliciesAPI) EffectiveActions(ctx context.Context, credential core.CredentialInput, input In[apitypes.PoliciesEffectiveActionsInput]) (Out[apitypes.PoliciesEffectiveActionsOutput], error) {
	return Out[apitypes.PoliciesEffectiveActionsOutput]{}, notImplemented("policies.effectiveActions")
}

// Get is POST {basePath}/policies/get. Returns one policy with its current document and version.
//
// STUB: returns NOT_IMPLEMENTED until api/policies.ts is ported.
func (api *PoliciesAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.PoliciesGetInput]) (Out[apitypes.PoliciesGetOutput], error) {
	return Out[apitypes.PoliciesGetOutput]{}, notImplemented("policies.get")
}

// List is POST {basePath}/policies/list. Lists every policy in the tenant at its current version, including the protected Owner policy.
//
// STUB: returns NOT_IMPLEMENTED until api/policies.ts is ported.
func (api *PoliciesAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.PoliciesListInput]) (Out[apitypes.PoliciesListOutput], error) {
	return Out[apitypes.PoliciesListOutput]{}, notImplemented("policies.list")
}

// ListVersions is POST {basePath}/policies/listVersions. Returns a policy's full history, oldest first, ending with the current version.
//
// STUB: returns NOT_IMPLEMENTED until api/policies.ts is ported.
func (api *PoliciesAPI) ListVersions(ctx context.Context, credential core.CredentialInput, input In[apitypes.PoliciesListVersionsInput]) (Out[apitypes.PoliciesListVersionsOutput], error) {
	return Out[apitypes.PoliciesListVersionsOutput]{}, notImplemented("policies.listVersions")
}

// RestoreVersion is POST {basePath}/policies/restoreVersion. Rolls a policy back to an earlier document by saving that document as a new version.
//
// STUB: returns NOT_IMPLEMENTED until api/policies.ts is ported.
func (api *PoliciesAPI) RestoreVersion(ctx context.Context, credential core.CredentialInput, input In[apitypes.PoliciesRestoreVersionInput]) (Out[apitypes.PoliciesRestoreVersionOutput], error) {
	return Out[apitypes.PoliciesRestoreVersionOutput]{}, notImplemented("policies.restoreVersion")
}

// Simulate is POST {basePath}/policies/simulate. Explains the decision one identity would get for one action on one resource, without creating a session or granting anything.
//
// STUB: returns NOT_IMPLEMENTED until api/policies.ts is ported.
func (api *PoliciesAPI) Simulate(ctx context.Context, credential core.CredentialInput, input In[apitypes.PoliciesSimulateInput]) (Out[apitypes.PoliciesSimulateOutput], error) {
	return Out[apitypes.PoliciesSimulateOutput]{}, notImplemented("policies.simulate")
}

// Test is POST {basePath}/policies/test. Evaluates an unsaved policy document against one action, resource, and context, for policy editors.
//
// STUB: returns NOT_IMPLEMENTED until api/policies.ts is ported.
func (api *PoliciesAPI) Test(ctx context.Context, credential core.CredentialInput, input In[apitypes.PoliciesTestInput]) (Out[apitypes.PoliciesTestOutput], error) {
	return Out[apitypes.PoliciesTestOutput]{}, notImplemented("policies.test")
}

// Update is POST {basePath}/policies/update. Saves a new version of a policy's document, name, or description, keeping the previous version in its history.
//
// STUB: returns NOT_IMPLEMENTED until api/policies.ts is ported.
func (api *PoliciesAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.PoliciesUpdateInput]) (Out[apitypes.PoliciesUpdateOutput], error) {
	return Out[apitypes.PoliciesUpdateOutput]{}, notImplemented("policies.update")
}

// WhoCan is POST {basePath}/policies/whoCan. Lists every active identity that could perform an action on a resource, with the reason, for access reviews.
//
// STUB: returns NOT_IMPLEMENTED until api/policies.ts is ported.
func (api *PoliciesAPI) WhoCan(ctx context.Context, credential core.CredentialInput, input In[apitypes.PoliciesWhoCanInput]) (Out[apitypes.PoliciesWhoCanOutput], error) {
	return Out[apitypes.PoliciesWhoCanOutput]{}, notImplemented("policies.whoCan")
}

// CreatePolicy (api/policies.ts createPolicy): Creates a policy under the caller's grant authority; shared by
// `policies.create` and configuration sync.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CreatePolicy(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenant *core.Object, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/policies.ts createPolicy")
	return
}

// DeletePolicy (api/policies.ts deletePolicy): Deletes a policy that no role still attaches; the Owner policy is
// protected.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DeletePolicy(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, policy *core.Object) (err error) {
	err = notImplemented("api/policies.ts deletePolicy")
	return
}

// UpdatePolicy (api/policies.ts updatePolicy): Updates a policy as a new version (optimistic concurrency on
// `version`); the previous version is retained.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func UpdatePolicy(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/policies.ts updatePolicy")
	return
}
