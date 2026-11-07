package server

// Skeleton of packages/server/src/applications.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// AppAccess (applications.ts appAccess): Whether a person may use an app, by its ID or its OAuth client: `governed:
// false` when no app in the catalog names the client (nothing to enforce). Refuses people of another tenant, an
// inactive tenant, and people who are not active.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AppAccess(ctx context.Context, server *ServerContext, tx core.IamStore, tenant *core.Object, identityID string, target *core.Object) (result *core.Object, err error) {
	err = notImplemented("applications.ts appAccess")
	return
}

// AppClientAllowed (applications.ts appClientAllowed): The OAuth provider's gate (`protocolHost.clientAllowed`): may
// this person get tokens for this client?
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AppClientAllowed(ctx context.Context, server *ServerContext, identityID string, tenantID string, clientID string) (result bool, err error) {
	err = notImplemented("applications.ts appClientAllowed")
	return
}

// AppHolders (applications.ts appHolders): How many people hold each app now, in one pass over the tenant (for usage
// reports): everyone apps count every eligible person, assigned apps the union of direct assignees and live members
// of assigned groups.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AppHolders(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, now int64) (result map[string]float64, err error) {
	err = notImplemented("applications.ts appHolders")
	return
}

// AppKey (applications.ts appKey): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AppKey(value any) (result string, err error) {
	err = notImplemented("applications.ts appKey")
	return
}

// AppURL (applications.ts appUrl): Launch and logo URLs: https, or http on the local machine when the deployment
// itself is local (development).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AppURL(value any, name string, allowLocal bool) (result string, err error) {
	err = notImplemented("applications.ts appUrl")
	return
}

// AppsFor (applications.ts appsFor): Which enabled apps a person may launch right now: everyone apps, apps assigned
// to them, and apps assigned to a group they belong to (memberships and assignments that have not ended). Only
// active, unexpired people have apps.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AppsFor(ctx context.Context, server *ServerContext, tx core.IamStore, identity *core.Object, now int64) (result map[string]*core.Object, err error) {
	err = notImplemented("applications.ts appsFor")
	return
}

// LocalDeployment (applications.ts localDeployment): Whether the deployment itself runs on the local machine
// (development), where apps may use plain http locally.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LocalDeployment(baseURL string) (result bool, err error) {
	err = notImplemented("applications.ts localDeployment")
	return
}

// ReleaseAppRecordsOf (applications.ts releaseAppRecordsOf): When a person is deleted: their assignments and launch
// history go, and they stop being an app owner.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ReleaseAppRecordsOf(ctx context.Context, tx core.IamStore, identity *core.Object) (err error) {
	err = notImplemented("applications.ts releaseAppRecordsOf")
	return
}

// ReleaseGroupApps (applications.ts releaseGroupApps): When a group is deleted: its app assignments go with it.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ReleaseGroupApps(ctx context.Context, tx core.IamStore, tenantID string, groupID string) (err error) {
	err = notImplemented("applications.ts releaseGroupApps")
	return
}
