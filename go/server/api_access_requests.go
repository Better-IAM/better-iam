package server

// Skeleton of packages/server/src/api/access-requests.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// AccessRequestsAPI is the `accessRequests` API group (packages/server/src/api/access-requests.ts createAccessRequestsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/accessRequests/{method} onto it.
type AccessRequestsAPI struct {
	server *ServerContext
}

// CreateAccessRequestsAPI builds the `accessRequests` API group.
func CreateAccessRequestsAPI(server *ServerContext) *AccessRequestsAPI {
	return &AccessRequestsAPI{server: server}
}

// Approve is POST {basePath}/accessRequests/approve. Approves a pending request, binding each requested role to the requester under your own grant authority.
//
// STUB: returns NOT_IMPLEMENTED until api/access-requests.ts is ported.
func (api *AccessRequestsAPI) Approve(ctx context.Context, credential core.CredentialInput, input In[apitypes.AccessRequestsApproveInput]) (Out[apitypes.AccessRequestsApproveOutput], error) {
	return Out[apitypes.AccessRequestsApproveOutput]{}, notImplemented("accessRequests.approve")
}

// Cancel is POST {basePath}/accessRequests/cancel. Withdraws one of your own pending requests.
//
// STUB: returns NOT_IMPLEMENTED until api/access-requests.ts is ported.
func (api *AccessRequestsAPI) Cancel(ctx context.Context, credential core.CredentialInput, input In[apitypes.AccessRequestsCancelInput]) (Out[apitypes.AccessRequestsCancelOutput], error) {
	return Out[apitypes.AccessRequestsCancelOutput]{}, notImplemented("accessRequests.cancel")
}

// Create is POST {basePath}/accessRequests/create. Asks for one or more roles for yourself, optionally for a limited time.
//
// STUB: returns NOT_IMPLEMENTED until api/access-requests.ts is ported.
func (api *AccessRequestsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.AccessRequestsCreateInput]) (Out[apitypes.AccessRequestsCreateOutput], error) {
	return Out[apitypes.AccessRequestsCreateOutput]{}, notImplemented("accessRequests.create")
}

// Deny is POST {basePath}/accessRequests/deny. Refuses a pending request, with an optional note for the requester.
//
// STUB: returns NOT_IMPLEMENTED until api/access-requests.ts is ported.
func (api *AccessRequestsAPI) Deny(ctx context.Context, credential core.CredentialInput, input In[apitypes.AccessRequestsDenyInput]) (Out[apitypes.AccessRequestsDenyOutput], error) {
	return Out[apitypes.AccessRequestsDenyOutput]{}, notImplemented("accessRequests.deny")
}

// Get is POST {basePath}/accessRequests/get. Returns one request.
//
// STUB: returns NOT_IMPLEMENTED until api/access-requests.ts is ported.
func (api *AccessRequestsAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.AccessRequestsGetInput]) (Out[apitypes.AccessRequestsGetOutput], error) {
	return Out[apitypes.AccessRequestsGetOutput]{}, notImplemented("accessRequests.get")
}

// List is POST {basePath}/accessRequests/list. Lists the tenant's requests, newest first, optionally by status or requester.
//
// STUB: returns NOT_IMPLEMENTED until api/access-requests.ts is ported.
func (api *AccessRequestsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.AccessRequestsListInput]) (Out[apitypes.AccessRequestsListOutput], error) {
	return Out[apitypes.AccessRequestsListOutput]{}, notImplemented("accessRequests.list")
}

// ListMine is POST {basePath}/accessRequests/listMine. Lists your own requests, newest first, optionally by status.
//
// STUB: returns NOT_IMPLEMENTED until api/access-requests.ts is ported.
func (api *AccessRequestsAPI) ListMine(ctx context.Context, credential core.CredentialInput, input In[apitypes.AccessRequestsListMineInput]) (Out[apitypes.AccessRequestsListMineOutput], error) {
	return Out[apitypes.AccessRequestsListMineOutput]{}, notImplemented("accessRequests.listMine")
}
