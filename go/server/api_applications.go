package server

// Skeleton of packages/server/src/api/applications.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// ApplicationsAPI is the `applications` API group (packages/server/src/api/applications.ts createApplicationsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/applications/{method} onto it.
type ApplicationsAPI struct {
	server *ServerContext
}

// CreateApplicationsAPI builds the `applications` API group.
func CreateApplicationsAPI(server *ServerContext) *ApplicationsAPI {
	return &ApplicationsAPI{server: server}
}

// Assign is POST {basePath}/applications/assign. Gives an app to a person or a group, optionally until expiresAt.
//
// STUB: returns NOT_IMPLEMENTED until api/applications.ts is ported.
func (api *ApplicationsAPI) Assign(ctx context.Context, credential core.CredentialInput, input In[apitypes.ApplicationsAssignInput]) (Out[apitypes.ApplicationsAssignOutput], error) {
	return Out[apitypes.ApplicationsAssignOutput]{}, notImplemented("applications.assign")
}

// Check is POST {basePath}/applications/check. Tells whether a person may use an app, by appId or by the app's oauthClientId, for sign-in pages that enforce assignments.
//
// STUB: returns NOT_IMPLEMENTED until api/applications.ts is ported.
func (api *ApplicationsAPI) Check(ctx context.Context, credential core.CredentialInput, input In[apitypes.ApplicationsCheckInput]) (Out[apitypes.ApplicationsCheckOutput], error) {
	return Out[apitypes.ApplicationsCheckOutput]{}, notImplemented("applications.check")
}

// Create is POST {basePath}/applications/create. Registers an app in the tenant's catalog: an OAuth client of this deployment, or a link to any tool.
//
// STUB: returns NOT_IMPLEMENTED until api/applications.ts is ported.
func (api *ApplicationsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.ApplicationsCreateInput]) (Out[apitypes.ApplicationsCreateOutput], error) {
	return Out[apitypes.ApplicationsCreateOutput]{}, notImplemented("applications.create")
}

// Delete is POST {basePath}/applications/delete. Deletes an app with its assignments and launch history.
//
// STUB: returns NOT_IMPLEMENTED until api/applications.ts is ported.
func (api *ApplicationsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.ApplicationsDeleteInput]) (Out[apitypes.ApplicationsDeleteOutput], error) {
	return Out[apitypes.ApplicationsDeleteOutput]{}, notImplemented("applications.delete")
}

// Launch is POST {basePath}/applications/launch. Opens an app the caller has: records the launch and returns the app's launch URL.
//
// STUB: returns NOT_IMPLEMENTED until api/applications.ts is ported.
func (api *ApplicationsAPI) Launch(ctx context.Context, credential core.CredentialInput, input In[apitypes.ApplicationsLaunchInput]) (Out[apitypes.ApplicationsLaunchOutput], error) {
	return Out[apitypes.ApplicationsLaunchOutput]{}, notImplemented("applications.launch")
}

// List is POST {basePath}/applications/list. Lists every app of the tenant by name, with how many live assignments each has and how many people opened it recently.
//
// STUB: returns NOT_IMPLEMENTED until api/applications.ts is ported.
func (api *ApplicationsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.ApplicationsListInput]) (Out[apitypes.ApplicationsListOutput], error) {
	return Out[apitypes.ApplicationsListOutput]{}, notImplemented("applications.list")
}

// ListAssignments is POST {basePath}/applications/listAssignments. Lists an app's assignments, or every app's, with who they name and when each person last opened the app.
//
// STUB: returns NOT_IMPLEMENTED until api/applications.ts is ported.
func (api *ApplicationsAPI) ListAssignments(ctx context.Context, credential core.CredentialInput, input In[apitypes.ApplicationsListAssignmentsInput]) (Out[apitypes.ApplicationsListAssignmentsOutput], error) {
	return Out[apitypes.ApplicationsListAssignmentsOutput]{}, notImplemented("applications.listAssignments")
}

// Mine is POST {basePath}/applications/mine. Returns the caller's launcher: the apps they may open now and the apps they may request.
//
// STUB: returns NOT_IMPLEMENTED until api/applications.ts is ported.
func (api *ApplicationsAPI) Mine(ctx context.Context, credential core.CredentialInput, input In[apitypes.ApplicationsMineInput]) (Out[apitypes.ApplicationsMineOutput], error) {
	return Out[apitypes.ApplicationsMineOutput]{}, notImplemented("applications.mine")
}

// RemoveUnused is POST {basePath}/applications/removeUnused. Removes an app's direct assignments to people who have not opened it for unusedDays.
//
// STUB: returns NOT_IMPLEMENTED until api/applications.ts is ported.
func (api *ApplicationsAPI) RemoveUnused(ctx context.Context, credential core.CredentialInput, input In[apitypes.ApplicationsRemoveUnusedInput]) (Out[apitypes.ApplicationsRemoveUnusedOutput], error) {
	return Out[apitypes.ApplicationsRemoveUnusedOutput]{}, notImplemented("applications.removeUnused")
}

// Unassign is POST {basePath}/applications/unassign. Removes one assignment of an app.
//
// STUB: returns NOT_IMPLEMENTED until api/applications.ts is ported.
func (api *ApplicationsAPI) Unassign(ctx context.Context, credential core.CredentialInput, input In[apitypes.ApplicationsUnassignInput]) (Out[apitypes.ApplicationsUnassignOutput], error) {
	return Out[apitypes.ApplicationsUnassignOutput]{}, notImplemented("applications.unassign")
}

// Update is POST {basePath}/applications/update. Changes an app's name, URLs, client, visibility, request package, owners, or whether it is enabled.
//
// STUB: returns NOT_IMPLEMENTED until api/applications.ts is ported.
func (api *ApplicationsAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.ApplicationsUpdateInput]) (Out[apitypes.ApplicationsUpdateOutput], error) {
	return Out[apitypes.ApplicationsUpdateOutput]{}, notImplemented("applications.update")
}

// Usage is POST {basePath}/applications/usage. Reports, per app, how many people have it, how many opened it in 30 days, and the direct assignments nobody uses.
//
// STUB: returns NOT_IMPLEMENTED until api/applications.ts is ported.
func (api *ApplicationsAPI) Usage(ctx context.Context, credential core.CredentialInput, input In[apitypes.ApplicationsUsageInput]) (Out[apitypes.ApplicationsUsageOutput], error) {
	return Out[apitypes.ApplicationsUsageOutput]{}, notImplemented("applications.usage")
}

// ApplicationsRuntime is api/applications.ts createApplicationsRuntime().
type ApplicationsRuntime struct {
	server *ServerContext
}

// Allowed (api/applications.ts createApplicationsRuntime().allowed): Whether `identityId` may use the app registered
// for `oauthClientId` (or `appId`). The built-in OAuth provider already enforces this for catalog clients; call it
// from other sign-in or consent pages. Ungoverned clients are allowed.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *ApplicationsRuntime) Allowed(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/applications.ts createApplicationsRuntime().allowed")
	return
}

// CreateApplicationsRuntime builds the ApplicationsRuntime (api/applications.ts createApplicationsRuntime). Its methods are stubs until the module is ported.
func CreateApplicationsRuntime(server *ServerContext) *ApplicationsRuntime {
	return &ApplicationsRuntime{server: server}
}
