package server

// Skeleton of packages/server/src/api/role-mining.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// RoleMiningAPI is the `roleMining` API group (packages/server/src/api/role-mining.ts createRoleMiningApi): every method runs through the
// operation envelope; the router maps POST {basePath}/roleMining/{method} onto it.
type RoleMiningAPI struct {
	server *ServerContext
}

// CreateRoleMiningAPI builds the `roleMining` API group.
func CreateRoleMiningAPI(server *ServerContext) *RoleMiningAPI {
	return &RoleMiningAPI{server: server}
}

// Apply is POST {basePath}/roleMining/apply. Carries out a group-binding or redundant-binding suggestion: binds the role to the group once and removes the direct bindings it replaces.
//
// STUB: returns NOT_IMPLEMENTED until api/role-mining.ts is ported.
func (api *RoleMiningAPI) Apply(ctx context.Context, credential core.CredentialInput, input In[apitypes.RoleMiningApplyInput]) (Out[apitypes.RoleMiningApplyOutput], error) {
	return Out[apitypes.RoleMiningApplyOutput]{}, notImplemented("roleMining.apply")
}

// Outliers is POST {basePath}/roleMining/outliers. Finds people whose roles differ from their peers': roles few peers hold and roles most peers hold that the person lacks.
//
// STUB: returns NOT_IMPLEMENTED until api/role-mining.ts is ported.
func (api *RoleMiningAPI) Outliers(ctx context.Context, credential core.CredentialInput, input In[apitypes.RoleMiningOutliersInput]) (Out[apitypes.RoleMiningOutliersOutput], error) {
	return Out[apitypes.RoleMiningOutliersOutput]{}, notImplemented("roleMining.outliers")
}

// ReviewRecommendations is POST {basePath}/roleMining/reviewRecommendations. Suggests a keep or revoke decision, with a reason, for every item of an access-certification campaign.
//
// STUB: returns NOT_IMPLEMENTED until api/role-mining.ts is ported.
func (api *RoleMiningAPI) ReviewRecommendations(ctx context.Context, credential core.CredentialInput, input In[apitypes.RoleMiningReviewRecommendationsInput]) (Out[apitypes.RoleMiningReviewRecommendationsOutput], error) {
	return Out[apitypes.RoleMiningReviewRecommendationsOutput]{}, notImplemented("roleMining.reviewRecommendations")
}

// RightSize is POST {basePath}/roleMining/rightSize. Lists every live binding whose holder used none or only some of the role's actions in a window, plus, per role, the actions nobody used.
//
// STUB: returns NOT_IMPLEMENTED until api/role-mining.ts is ported.
func (api *RoleMiningAPI) RightSize(ctx context.Context, credential core.CredentialInput, input In[apitypes.RoleMiningRightSizeInput]) (Out[apitypes.RoleMiningRightSizeOutput], error) {
	return Out[apitypes.RoleMiningRightSizeOutput]{}, notImplemented("roleMining.rightSize")
}

// Suggest is POST {basePath}/roleMining/suggest. Lists ways to simplify how the tenant grants access, most actionable first.
//
// STUB: returns NOT_IMPLEMENTED until api/role-mining.ts is ported.
func (api *RoleMiningAPI) Suggest(ctx context.Context, credential core.CredentialInput, input In[apitypes.RoleMiningSuggestInput]) (Out[apitypes.RoleMiningSuggestOutput], error) {
	return Out[apitypes.RoleMiningSuggestOutput]{}, notImplemented("roleMining.suggest")
}

// Usage is POST {basePath}/roleMining/usage. Returns the recorded access usage of the tenant: per person and action, when it was first and last allowed and how often.
//
// STUB: returns NOT_IMPLEMENTED until api/role-mining.ts is ported.
func (api *RoleMiningAPI) Usage(ctx context.Context, credential core.CredentialInput, input In[apitypes.RoleMiningUsageInput]) (Out[apitypes.RoleMiningUsageOutput], error) {
	return Out[apitypes.RoleMiningUsageOutput]{}, notImplemented("roleMining.usage")
}
