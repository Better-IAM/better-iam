package server

// Skeleton of packages/server/src/api/security.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// SecurityAPI is the `security` API group (packages/server/src/api/security.ts createSecurityApi): every method runs through the
// operation envelope; the router maps POST {basePath}/security/{method} onto it.
type SecurityAPI struct {
	server *ServerContext
}

// CreateSecurityAPI builds the `security` API group.
func CreateSecurityAPI(server *ServerContext) *SecurityAPI {
	return &SecurityAPI{server: server}
}

// BlockNetwork is POST {basePath}/security/blockNetwork. Blocks an IP address or CIDR range for the tenant, or for the whole platform, optionally for a limited time.
//
// STUB: returns NOT_IMPLEMENTED until api/security.ts is ported.
func (api *SecurityAPI) BlockNetwork(ctx context.Context, credential core.CredentialInput, input In[apitypes.SecurityBlockNetworkInput]) (Out[apitypes.SecurityBlockNetworkOutput], error) {
	return Out[apitypes.SecurityBlockNetworkOutput]{}, notImplemented("security.blockNetwork")
}

// ListBlocks is POST {basePath}/security/listBlocks. Lists the tenant's network blocks, newest first, each with active telling whether it still applies.
//
// STUB: returns NOT_IMPLEMENTED until api/security.ts is ported.
func (api *SecurityAPI) ListBlocks(ctx context.Context, credential core.CredentialInput, input In[apitypes.SecurityListBlocksInput]) (Out[apitypes.SecurityListBlocksOutput], error) {
	return Out[apitypes.SecurityListBlocksOutput]{}, notImplemented("security.listBlocks")
}

// UnblockNetwork is POST {basePath}/security/unblockNetwork. Lifts a network block before it lapses.
//
// STUB: returns NOT_IMPLEMENTED until api/security.ts is ported.
func (api *SecurityAPI) UnblockNetwork(ctx context.Context, credential core.CredentialInput, input In[apitypes.SecurityUnblockNetworkInput]) (Out[apitypes.SecurityUnblockNetworkOutput], error) {
	return Out[apitypes.SecurityUnblockNetworkOutput]{}, notImplemented("security.unblockNetwork")
}
