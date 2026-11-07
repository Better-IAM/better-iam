package server

// Skeleton of packages/server/src/api/access-paths.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// AccessPathsAPI is the `accessPaths` API group (packages/server/src/api/access-paths.ts createAccessPathsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/accessPaths/{method} onto it.
type AccessPathsAPI struct {
	server *ServerContext
}

// CreateAccessPathsAPI builds the `accessPaths` API group.
func CreateAccessPathsAPI(server *ServerContext) *AccessPathsAPI {
	return &AccessPathsAPI{server: server}
}

// Find is POST {basePath}/accessPaths/find. Lists what you could do yourself to be allowed an action on a resource you are denied.
//
// STUB: returns NOT_IMPLEMENTED until api/access-paths.ts is ported.
func (api *AccessPathsAPI) Find(ctx context.Context, credential core.CredentialInput, input In[apitypes.AccessPathsFindInput]) (Out[apitypes.AccessPathsFindOutput], error) {
	return Out[apitypes.AccessPathsFindOutput]{}, notImplemented("accessPaths.find")
}
