package server

// Skeleton of packages/server/src/api/impact.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// ImpactAPI is the `impact` API group (packages/server/src/api/impact.ts createImpactApi): every method runs through the
// operation envelope; the router maps POST {basePath}/impact/{method} onto it.
type ImpactAPI struct {
	server *ServerContext
}

// CreateImpactAPI builds the `impact` API group.
func CreateImpactAPI(server *ServerContext) *ImpactAPI {
	return &ImpactAPI{server: server}
}

// Preview is POST {basePath}/impact/preview. Simulates a role update, a policy document change, or a role deletion, and reports the actions each holder would gain and lose per resource, plus the access invariants the change would break or fix.
//
// STUB: returns NOT_IMPLEMENTED until api/impact.ts is ported.
func (api *ImpactAPI) Preview(ctx context.Context, credential core.CredentialInput, input In[apitypes.ImpactPreviewInput]) (Out[apitypes.ImpactPreviewOutput], error) {
	return Out[apitypes.ImpactPreviewOutput]{}, notImplemented("impact.preview")
}
