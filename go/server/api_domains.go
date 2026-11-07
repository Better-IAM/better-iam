package server

// Skeleton of packages/server/src/api/domains.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// DomainsAPI is the `domains` API group (packages/server/src/api/domains.ts createDomainsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/domains/{method} onto it.
type DomainsAPI struct {
	server *ServerContext
}

// CreateDomainsAPI builds the `domains` API group.
func CreateDomainsAPI(server *ServerContext) *DomainsAPI {
	return &DomainsAPI{server: server}
}

// Add is POST {basePath}/domains/add. Claims a domain for the tenant and returns the TXT record the organization must publish to prove control.
//
// STUB: returns NOT_IMPLEMENTED until api/domains.ts is ported.
func (api *DomainsAPI) Add(ctx context.Context, credential core.CredentialInput, input In[apitypes.DomainsAddInput]) (Out[apitypes.DomainsAddOutput], error) {
	return Out[apitypes.DomainsAddOutput]{}, notImplemented("domains.add")
}

// Delete is POST {basePath}/domains/delete. Releases a domain claim; a verified domain stops resolving to the tenant immediately.
//
// STUB: returns NOT_IMPLEMENTED until api/domains.ts is ported.
func (api *DomainsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.DomainsDeleteInput]) (Out[apitypes.DomainsDeleteOutput], error) {
	return Out[apitypes.DomainsDeleteOutput]{}, notImplemented("domains.delete")
}

// Discover is POST {basePath}/domains/discover (public: no request credential). Finds the organization that verified an email address's domain, with the sign-in rules it enforces.
//
// STUB: returns NOT_IMPLEMENTED until api/domains.ts is ported.
func (api *DomainsAPI) Discover(ctx context.Context, input In[apitypes.DomainsDiscoverInput]) (Out[apitypes.DomainsDiscoverOutput], error) {
	return Out[apitypes.DomainsDiscoverOutput]{}, notImplemented("domains.discover")
}

// List is POST {basePath}/domains/list. Lists the tenant's claimed domains, newest first, with their status and the TXT record each one needs.
//
// STUB: returns NOT_IMPLEMENTED until api/domains.ts is ported.
func (api *DomainsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.DomainsListInput]) (Out[apitypes.DomainsListOutput], error) {
	return Out[apitypes.DomainsListOutput]{}, notImplemented("domains.list")
}

// Verify is POST {basePath}/domains/verify. Looks up the domain's TXT record and marks the claim verified when the record matches.
//
// STUB: returns NOT_IMPLEMENTED until api/domains.ts is ported.
func (api *DomainsAPI) Verify(ctx context.Context, credential core.CredentialInput, input In[apitypes.DomainsVerifyInput]) (Out[apitypes.DomainsVerifyOutput], error) {
	return Out[apitypes.DomainsVerifyOutput]{}, notImplemented("domains.verify")
}

// DomainName (api/domains.ts domainName): Normalizes and validates a registrable-looking DNS name: lowercase, no
// trailing dot, alphabetic TLD.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DomainName(value any) (result string, err error) {
	err = notImplemented("api/domains.ts domainName")
	return
}

// PermittedAhead (api/domains.ts permittedAhead): The decision `operation` makes (`action` on `iam/{resourceId}`),
// taken ahead of work that must happen outside its transaction, such as a DNS query, so that work is done only for a
// caller the operation will admit. A refusal is not recorded here: the operation that follows refuses the caller
// again and records it.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PermittedAhead(ctx context.Context, server *ServerContext, credential core.CredentialInput, tenantID string, action string, resourceID string) (result bool, err error) {
	err = notImplemented("api/domains.ts permittedAhead")
	return
}
