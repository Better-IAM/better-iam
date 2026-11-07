package server

// Skeleton of packages/server/src/api/oidc-providers.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// OidcProvidersAPI is the `oidcProviders` API group (packages/server/src/api/oidc-providers.ts createOidcProvidersApi): every method runs through the
// operation envelope; the router maps POST {basePath}/oidcProviders/{method} onto it.
type OidcProvidersAPI struct {
	server *ServerContext
}

// CreateOidcProvidersAPI builds the `oidcProviders` API group.
func CreateOidcProvidersAPI(server *ServerContext) *OidcProvidersAPI {
	return &OidcProvidersAPI{server: server}
}

// Create is POST {basePath}/oidcProviders/create. Registers an OIDC provider whose tokens the tenant's web-identity trusts can admit.
//
// STUB: returns NOT_IMPLEMENTED until api/oidc-providers.ts is ported.
func (api *OidcProvidersAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.OidcProvidersCreateInput]) (Out[apitypes.OidcProvidersCreateOutput], error) {
	return Out[apitypes.OidcProvidersCreateOutput]{}, notImplemented("oidcProviders.create")
}

// Delete is POST {basePath}/oidcProviders/delete. Deletes a provider that no live trust uses any more.
//
// STUB: returns NOT_IMPLEMENTED until api/oidc-providers.ts is ported.
func (api *OidcProvidersAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.OidcProvidersDeleteInput]) (Out[apitypes.OidcProvidersDeleteOutput], error) {
	return Out[apitypes.OidcProvidersDeleteOutput]{}, notImplemented("oidcProviders.delete")
}

// Get is POST {basePath}/oidcProviders/get. Returns one provider.
//
// STUB: returns NOT_IMPLEMENTED until api/oidc-providers.ts is ported.
func (api *OidcProvidersAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.OidcProvidersGetInput]) (Out[apitypes.OidcProvidersGetOutput], error) {
	return Out[apitypes.OidcProvidersGetOutput]{}, notImplemented("oidcProviders.get")
}

// List is POST {basePath}/oidcProviders/list. Lists the tenant's OIDC providers, oldest first.
//
// STUB: returns NOT_IMPLEMENTED until api/oidc-providers.ts is ported.
func (api *OidcProvidersAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.OidcProvidersListInput]) (Out[apitypes.OidcProvidersListOutput], error) {
	return Out[apitypes.OidcProvidersListOutput]{}, notImplemented("oidcProviders.list")
}

// RevokeSessions is POST {basePath}/oidcProviders/revokeSessions. Ends the web-identity sessions issued through a provider before a point in time, across every trust that uses it.
//
// STUB: returns NOT_IMPLEMENTED until api/oidc-providers.ts is ported.
func (api *OidcProvidersAPI) RevokeSessions(ctx context.Context, credential core.CredentialInput, input In[apitypes.OidcProvidersRevokeSessionsInput]) (Out[apitypes.OidcProvidersRevokeSessionsOutput], error) {
	return Out[apitypes.OidcProvidersRevokeSessionsOutput]{}, notImplemented("oidcProviders.revokeSessions")
}

// Update is POST {basePath}/oidcProviders/update. Changes a provider's name, audiences, keys, algorithms, token limits, replay protection, or enabled state.
//
// STUB: returns NOT_IMPLEMENTED until api/oidc-providers.ts is ported.
func (api *OidcProvidersAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.OidcProvidersUpdateInput]) (Out[apitypes.OidcProvidersUpdateOutput], error) {
	return Out[apitypes.OidcProvidersUpdateOutput]{}, notImplemented("oidcProviders.update")
}
