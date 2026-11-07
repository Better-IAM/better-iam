package server

// Skeleton of packages/server/src/api/service-accounts.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// ServiceAccountsAPI is the `serviceAccounts` API group (packages/server/src/api/service-accounts.ts createServiceAccountsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/serviceAccounts/{method} onto it.
type ServiceAccountsAPI struct {
	server *ServerContext
}

// CreateServiceAccountsAPI builds the `serviceAccounts` API group.
func CreateServiceAccountsAPI(server *ServerContext) *ServiceAccountsAPI {
	return &ServiceAccountsAPI{server: server}
}

// Create is POST {basePath}/serviceAccounts/create. Creates a service account in the tenant, optionally with a date after which it is deactivated.
//
// STUB: returns NOT_IMPLEMENTED until api/service-accounts.ts is ported.
func (api *ServiceAccountsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.ServiceAccountsCreateInput]) (Out[apitypes.ServiceAccountsCreateOutput], error) {
	return Out[apitypes.ServiceAccountsCreateOutput]{}, notImplemented("serviceAccounts.create")
}

// Delete is POST {basePath}/serviceAccounts/delete. Deletes a service account, revoking its keys and removing every grant it held.
//
// STUB: returns NOT_IMPLEMENTED until api/service-accounts.ts is ported.
func (api *ServiceAccountsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.ServiceAccountsDeleteInput]) (Out[apitypes.ServiceAccountsDeleteOutput], error) {
	return Out[apitypes.ServiceAccountsDeleteOutput]{}, notImplemented("serviceAccounts.delete")
}

// Get is POST {basePath}/serviceAccounts/get. Returns one service account by id.
//
// STUB: returns NOT_IMPLEMENTED until api/service-accounts.ts is ported.
func (api *ServiceAccountsAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.ServiceAccountsGetInput]) (Out[apitypes.ServiceAccountsGetOutput], error) {
	return Out[apitypes.ServiceAccountsGetOutput]{}, notImplemented("serviceAccounts.get")
}

// List is POST {basePath}/serviceAccounts/list. Lists the tenant's service accounts, without deleted ones unless you ask for them.
//
// STUB: returns NOT_IMPLEMENTED until api/service-accounts.ts is ported.
func (api *ServiceAccountsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.ServiceAccountsListInput]) (Out[apitypes.ServiceAccountsListOutput], error) {
	return Out[apitypes.ServiceAccountsListOutput]{}, notImplemented("serviceAccounts.list")
}

// SetStatus is POST {basePath}/serviceAccounts/setStatus. Disables a service account, ending all its access at once, or enables it again.
//
// STUB: returns NOT_IMPLEMENTED until api/service-accounts.ts is ported.
func (api *ServiceAccountsAPI) SetStatus(ctx context.Context, credential core.CredentialInput, input In[apitypes.ServiceAccountsSetStatusInput]) (Out[apitypes.ServiceAccountsSetStatusOutput], error) {
	return Out[apitypes.ServiceAccountsSetStatusOutput]{}, notImplemented("serviceAccounts.setStatus")
}

// Update is POST {basePath}/serviceAccounts/update. Renames a service account, changes its description or directory attributes, or schedules or clears its deactivation.
//
// STUB: returns NOT_IMPLEMENTED until api/service-accounts.ts is ported.
func (api *ServiceAccountsAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.ServiceAccountsUpdateInput]) (Out[apitypes.ServiceAccountsUpdateOutput], error) {
	return Out[apitypes.ServiceAccountsUpdateOutput]{}, notImplemented("serviceAccounts.update")
}

// CredentialsAPI is the `credentials` API group (packages/server/src/api/service-accounts.ts createCredentialsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/credentials/{method} onto it.
type CredentialsAPI struct {
	server *ServerContext
}

// CreateCredentialsAPI builds the `credentials` API group.
func CreateCredentialsAPI(server *ServerContext) *CredentialsAPI {
	return &CredentialsAPI{server: server}
}

// Create is POST {basePath}/credentials/create. Issues an API key for an active service account and returns its token, which is shown only once.
//
// STUB: returns NOT_IMPLEMENTED until api/service-accounts.ts is ported.
func (api *CredentialsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.CredentialsCreateInput]) (Out[apitypes.CredentialsCreateOutput], error) {
	return Out[apitypes.CredentialsCreateOutput]{}, notImplemented("credentials.create")
}

// Get is POST {basePath}/credentials/get. Returns one API key's label, lifetime, scopes, and last use, without token material.
//
// STUB: returns NOT_IMPLEMENTED until api/service-accounts.ts is ported.
func (api *CredentialsAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.CredentialsGetInput]) (Out[apitypes.CredentialsGetOutput], error) {
	return Out[apitypes.CredentialsGetOutput]{}, notImplemented("credentials.get")
}

// List is POST {basePath}/credentials/list. Lists the API keys of the tenant or of one service account, newest first, optionally only the unused ones.
//
// STUB: returns NOT_IMPLEMENTED until api/service-accounts.ts is ported.
func (api *CredentialsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.CredentialsListInput]) (Out[apitypes.CredentialsListOutput], error) {
	return Out[apitypes.CredentialsListOutput]{}, notImplemented("credentials.list")
}

// Revoke is POST {basePath}/credentials/revoke. Deletes an API key so it stops working immediately.
//
// STUB: returns NOT_IMPLEMENTED until api/service-accounts.ts is ported.
func (api *CredentialsAPI) Revoke(ctx context.Context, credential core.CredentialInput, input In[apitypes.CredentialsRevokeInput]) (Out[apitypes.CredentialsRevokeOutput], error) {
	return Out[apitypes.CredentialsRevokeOutput]{}, notImplemented("credentials.revoke")
}

// Rotate is POST {basePath}/credentials/rotate. Replaces an API key with a new token in one transaction, so the old token stops working the moment the new one exists.
//
// STUB: returns NOT_IMPLEMENTED until api/service-accounts.ts is ported.
func (api *CredentialsAPI) Rotate(ctx context.Context, credential core.CredentialInput, input In[apitypes.CredentialsRotateInput]) (Out[apitypes.CredentialsRotateOutput], error) {
	return Out[apitypes.CredentialsRotateOutput]{}, notImplemented("credentials.rotate")
}

// Update is POST {basePath}/credentials/update. Relabels an API key or moves its expiry; the token itself does not change.
//
// STUB: returns NOT_IMPLEMENTED until api/service-accounts.ts is ported.
func (api *CredentialsAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.CredentialsUpdateInput]) (Out[apitypes.CredentialsUpdateOutput], error) {
	return Out[apitypes.CredentialsUpdateOutput]{}, notImplemented("credentials.update")
}

// CredentialSummary (api/service-accounts.ts credentialSummary): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CredentialSummary(session *core.Object, now int64) (result *core.Object, err error) {
	err = notImplemented("api/service-accounts.ts credentialSummary")
	return
}
