package server

// Skeleton of packages/server/src/api/hostnames.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// HostnamesAPI is the `hostnames` API group (packages/server/src/api/hostnames.ts createHostnamesApi): every method runs through the
// operation envelope; the router maps POST {basePath}/hostnames/{method} onto it.
type HostnamesAPI struct {
	server *ServerContext
}

// CreateHostnamesAPI builds the `hostnames` API group.
func CreateHostnamesAPI(server *ServerContext) *HostnamesAPI {
	return &HostnamesAPI{server: server}
}

// Add is POST {basePath}/hostnames/add. Claims a hostname for the organization and returns the DNS records that verify and route it.
//
// STUB: returns NOT_IMPLEMENTED until api/hostnames.ts is ported.
func (api *HostnamesAPI) Add(ctx context.Context, credential core.CredentialInput, input In[apitypes.HostnamesAddInput]) (Out[apitypes.HostnamesAddOutput], error) {
	return Out[apitypes.HostnamesAddOutput]{}, notImplemented("hostnames.add")
}

// Delete is POST {basePath}/hostnames/delete. Releases a hostname; a verified one stops resolving to the organization at once.
//
// STUB: returns NOT_IMPLEMENTED until api/hostnames.ts is ported.
func (api *HostnamesAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.HostnamesDeleteInput]) (Out[apitypes.HostnamesDeleteOutput], error) {
	return Out[apitypes.HostnamesDeleteOutput]{}, notImplemented("hostnames.delete")
}

// List is POST {basePath}/hostnames/list. Lists the organization's claimed hostnames, newest first, with their status and DNS records.
//
// STUB: returns NOT_IMPLEMENTED until api/hostnames.ts is ported.
func (api *HostnamesAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.HostnamesListInput]) (Out[apitypes.HostnamesListOutput], error) {
	return Out[apitypes.HostnamesListOutput]{}, notImplemented("hostnames.list")
}

// SetPrimary is POST {basePath}/hostnames/setPrimary. Makes a verified hostname the organization's canonical sign-in address, or goes back to its subdomain.
//
// STUB: returns NOT_IMPLEMENTED until api/hostnames.ts is ported.
func (api *HostnamesAPI) SetPrimary(ctx context.Context, credential core.CredentialInput, input In[apitypes.HostnamesSetPrimaryInput]) (Out[apitypes.HostnamesSetPrimaryOutput], error) {
	return Out[apitypes.HostnamesSetPrimaryOutput]{}, notImplemented("hostnames.setPrimary")
}

// Verify is POST {basePath}/hostnames/verify. Looks up the hostname's TXT record and, when it matches, marks the hostname verified so it starts resolving to the organization.
//
// STUB: returns NOT_IMPLEMENTED until api/hostnames.ts is ported.
func (api *HostnamesAPI) Verify(ctx context.Context, credential core.CredentialInput, input In[apitypes.HostnamesVerifyInput]) (Out[apitypes.HostnamesVerifyOutput], error) {
	return Out[apitypes.HostnamesVerifyOutput]{}, notImplemented("hostnames.verify")
}
