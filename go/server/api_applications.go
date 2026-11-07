package server

// Port of packages/server/src/api/applications.ts: the application catalog and the "My apps" launcher.
// Administrators register apps (an OAuth client of this deployment, or a link to any tool) and assign them to people
// and groups (`iam:applications:manage`, `iam:applications:assign`, reading `iam:applications:read`); people see and
// launch their apps, and request the ones they lack, without a permission. For an OpenID Connect app the OAuth
// provider enforces the assignment (`iam.protocolHost.clientAllowed`); `check` (and `iam.applications.allowed`)
// answers the same question for other sign-in pages. People's names and addresses appear only for callers who may
// read the directory.

import (
	"context"
	"fmt"
	"math"
	"sort"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

const (
	maxApps              = 500
	maxAssignmentsPerApp = 10_000
	appDayMs             = 86_400_000
)

// appNameText is api/applications.ts nameText: text(value, name, max).trim().
func appNameText(value any, name string, max int) (string, error) {
	text, err := Text(value, name, max)
	if err != nil {
		return "", err
	}
	return core.JSTrim(text), nil
}

// strictEquals is JavaScript `a === b` over model values: primitives by value, objects and arrays by reference.
func strictEquals(a, b any) bool {
	switch x := a.(type) {
	case *core.Object:
		y, ok := b.(*core.Object)
		return ok && x == y
	case string, float64, bool, nil, core.UndefinedType:
		switch b.(type) {
		case string, float64, bool, nil, core.UndefinedType:
			return a == b
		}
	}
	return false
}

// optionalString is a record member that TypeScript types as `string | undefined`: the string, or "" when absent.
func optionalString(record *core.Object, key string) string {
	if record == nil {
		return ""
	}
	value, _ := record.Get(key).(string)
	return value
}

// selfSession is api/applications.ts selfSession: the launcher is for people signed in to their organization.
func selfSession(principal *Principal, tenantID string) error {
	if !ActsInOwnRight(principal.Session) || principal.Session.Get("kind") != "user" ||
		principal.Session.Get("tenantId") != tenantID || principal.Identity.Get("tenantId") != tenantID ||
		principal.Identity.Get("kind") != "user" {
		return core.NewIamError("ACCESS_DENIED", "The launcher is for people signed in to their organization", 403)
	}
	return nil
}

// appFields is api/applications.ts appFields: the validated members of an app, from the input and (on update) the
// previous record, in the TypeScript validation order.
func appFields(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, input *core.Object, previous *core.Object) (*core.Object, error) {
	var key string
	if previous != nil {
		key = jsString(previous.Get("key"))
	} else {
		validated, err := AppKey(input.Get("key"))
		if err != nil {
			return nil, err
		}
		key = validated
	}
	if previous != nil && !isUndefined(input.Get("key")) && !strictEquals(input.Get("key"), previous.Get("key")) {
		return nil, invalidInput("An app key cannot change")
	}
	allowLocal, _ := LocalDeployment(server.Options.BaseURL)
	previousID := ""
	if previous != nil {
		previousID = jsString(previous.Get("id"))
	}
	// oauthClientId: "" stands for undefined (text() never accepts a blank value).
	oauthClientID := optionalString(previous, "oauthClientId")
	if given := input.Get("oauthClientId"); !isUndefined(given) {
		if given == nil || given == "" {
			oauthClientID = ""
		} else {
			validated, err := Text(given, "oauthClientId", 256)
			if err != nil {
				return nil, err
			}
			oauthClientID = validated
		}
	}
	if oauthClientID != "" && oauthClientID != optionalString(previous, "oauthClientId") {
		clients, err := tx.Find(ctx, "oauthClients", core.NewObject("tenantId", tenantID, "clientId", oauthClientID), nil)
		if err != nil {
			return nil, err
		}
		if len(clients) == 0 || clients[0].Get("revoked") == true {
			return nil, invalidInput("oauthClientId must name an OAuth client of this organization")
		}
		// One app per client: two would make whether someone may sign in depend on which one is found first.
		apps, err := tx.Find(ctx, "applications", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		for _, app := range apps {
			if app.Get("oauthClientId") == oauthClientID && (previous == nil || jsString(app.Get("id")) != previousID) {
				return nil, core.NewIamError("CONFLICT", fmt.Sprintf("App %s already governs this OAuth client", jsString(app.Get("key"))), 409)
			}
		}
	}
	requestPackageID := optionalString(previous, "requestPackageId")
	if given := input.Get("requestPackageId"); !isUndefined(given) {
		if given == nil || given == "" {
			requestPackageID = ""
		} else {
			validated, err := Text(given, "requestPackageId")
			if err != nil {
				return nil, err
			}
			requestPackageID = validated
		}
	}
	if requestPackageID != "" && requestPackageID != optionalString(previous, "requestPackageId") {
		pkg, err := server.Scoped(ctx, tx, "accessPackages", requestPackageID, tenantID)
		if err != nil {
			return nil, err
		}
		if !truthy(pkg.Get("requestable")) {
			return nil, invalidInput("requestPackageId must name a package members may request")
		}
	}
	// Owners are checked when they are set; an owner deleted later never blocks editing (or disabling) the app.
	ownerIDs := any([]any{})
	if previous != nil && !nullish(previous.Get("ownerIds")) {
		ownerIDs = previous.Get("ownerIds")
	}
	if given := input.Get("ownerIds"); !isUndefined(given) {
		list, err := Strings(given, "ownerIds")
		if err != nil {
			return nil, err
		}
		owners := unique(list)
		if len(owners) > 20 {
			return nil, invalidInput("At most 20 owners")
		}
		for _, ownerID := range owners {
			if _, err := server.ActiveIdentity(ctx, tx, ownerID, tenantID); err != nil {
				return nil, err
			}
		}
		ownerIDs = stringsOf(owners)
	}
	visibility := coalesce(input.Get("visibility"), coalesce(member(previous, "visibility"), "assigned"))
	if visibility != "everyone" && visibility != "assigned" {
		return nil, invalidInput("visibility must be 'everyone' or 'assigned'")
	}
	enabled := coalesce(input.Get("enabled"), coalesce(member(previous, "enabled"), true))
	if _, ok := enabled.(bool); !ok {
		return nil, invalidInput("enabled must be a boolean")
	}
	optional := func(value any, prior string, name string, max int) (string, error) {
		if isUndefined(value) {
			return prior, nil
		}
		if value == nil || value == "" {
			return "", nil
		}
		return appNameText(value, name, max)
	}
	description, err := optional(input.Get("description"), optionalString(previous, "description"), "description", 1000)
	if err != nil {
		return nil, err
	}
	category, err := optional(input.Get("category"), optionalString(previous, "category"), "category", 60)
	if err != nil {
		return nil, err
	}
	logoURL := optionalString(previous, "logoUrl")
	if given := input.Get("logoUrl"); !isUndefined(given) {
		if given == nil || given == "" {
			logoURL = ""
		} else if logoURL, err = AppURL(given, "logoUrl", allowLocal); err != nil {
			return nil, err
		}
	}
	var launchURL any
	if isUndefined(input.Get("launchUrl")) && previous != nil {
		launchURL = previous.Get("launchUrl")
	} else {
		validated, err := AppURL(input.Get("launchUrl"), "launchUrl", allowLocal)
		if err != nil {
			return nil, err
		}
		launchURL = validated
	}
	name, err := appNameText(coalesce(input.Get("name"), member(previous, "name")), "name", 120)
	if err != nil {
		return nil, err
	}
	values := core.NewObject("uniqueKey", "key:"+key, "key", key, "name", name)
	if description != "" {
		values.Set("description", description)
	}
	if category != "" {
		values.Set("category", category)
	}
	values.Set("launchUrl", launchURL)
	if logoURL != "" {
		values.Set("logoUrl", logoURL)
	}
	if oauthClientID != "" {
		values.Set("kind", "oidc")
		values.Set("oauthClientId", oauthClientID)
	} else {
		values.Set("kind", "link")
	}
	values.Set("visibility", visibility)
	values.Set("enabled", enabled)
	if requestPackageID != "" {
		values.Set("requestPackageId", requestPackageID)
	}
	values.Set("ownerIds", ownerIDs)
	return values, nil
}

// appState is api/applications.ts appState: what an audit event records about an app's state.
func appState(app *core.Object) *core.Object {
	state := core.NewObject("name", app.Get("name"), "launchUrl", app.Get("launchUrl"), "visibility", app.Get("visibility"),
		"enabled", app.Get("enabled"))
	if truthy(app.Get("oauthClientId")) {
		state.Set("oauthClientId", app.Get("oauthClientId"))
	}
	if truthy(app.Get("requestPackageId")) {
		state.Set("requestPackageId", app.Get("requestPackageId"))
	}
	return state
}

// directory is api/applications.ts directory: may the caller see people's names and addresses
// (`iam:identities:read`)?
func (api *ApplicationsAPI) directory(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string) (bool, error) {
	decision, err := api.server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{
		TenantID: tenantID, Action: "iam:identities:read", Resource: ResourceTarget{Type: "iam", ID: tenantID},
	}, true)
	if err != nil {
		return false, err
	}
	return decision.Allowed, nil
}

// audit is api/applications.ts audit: an allowed event with metadata.
func (api *ApplicationsAPI) audit(ctx context.Context, tx core.IamStore, principal *Principal, action, tenantID, resourceID string, metadata *core.Object) error {
	return api.server.Events.Audit(ctx, tx, principal, action, tenantID, resourceID, "allow", false, metadata)
}

// assertReleased is api/applications.ts assertReleased: governing a client stops only on purpose, since without the
// app everyone of the tenant may sign in to it.
func assertReleased(app *core.Object, releaseClient any) error {
	if truthy(app.Get("oauthClientId")) && releaseClient != true {
		return core.NewIamError("CONFLICT", fmt.Sprintf(
			"%s decides who may sign in to OAuth client %s; without it everyone of the organization may. Pass releaseClient: true to confirm.",
			jsString(app.Get("name")), jsString(app.Get("oauthClientId"))), 409)
	}
	return nil
}

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
// Audited as `app:assign`.
func (api *ApplicationsAPI) Assign(ctx context.Context, credential core.CredentialInput, input In[apitypes.ApplicationsAssignInput]) (Out[apitypes.ApplicationsAssignOutput], error) {
	appID, err := Text(input.Get("appId"), "appId")
	if err != nil {
		return Out[apitypes.ApplicationsAssignOutput]{}, err
	}
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:applications:assign", appID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		tenantID := jsString(call.Tenant.Get("id"))
		app, err := server.Scoped(ctx, tx, "applications", input.Get("appId"), tenantID)
		if err != nil {
			return nil, err
		}
		subjectType := input.Get("subjectType")
		if subjectType != "identity" && subjectType != "group" {
			return nil, invalidInput("subjectType must be 'identity' or 'group'")
		}
		subjectID, err := Text(input.Get("subjectId"), "subjectId")
		if err != nil {
			return nil, err
		}
		if subjectType == "identity" {
			identity, err := server.ActiveIdentity(ctx, tx, subjectID, tenantID)
			if err != nil {
				return nil, err
			}
			if identity.Get("kind") != "user" {
				return nil, invalidInput("Apps are assigned to people and groups")
			}
		} else if _, err := server.Scoped(ctx, tx, "groups", subjectID, tenantID); err != nil {
			return nil, err
		}
		var expiresAt any = core.Undefined
		if given := input.Get("expiresAt"); !isUndefined(given) {
			value, err := server.BindingExpiry(given)
			if err != nil {
				return nil, err
			}
			expiresAt = value
		}
		uniqueKey := jsString(app.Get("id")) + ":" + jsString(subjectType) + ":" + subjectID
		found, err := tx.Find(ctx, "appAssignments", core.NewObject("tenantId", tenantID, "uniqueKey", uniqueKey), nil)
		if err != nil {
			return nil, err
		}
		var existing *core.Object
		if len(found) > 0 {
			existing = found[0]
		}
		if existing == nil {
			assigned, err := tx.Find(ctx, "appAssignments", core.NewObject("tenantId", tenantID, "appId", app.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			if len(assigned) >= maxAssignmentsPerApp {
				return nil, core.NewIamError("LIMIT_EXCEEDED", fmt.Sprintf("At most %d assignments per app; assign groups instead", maxAssignmentsPerApp), 409)
			}
		}
		now := server.Now()
		var id any
		if existing != nil {
			id = existing.Get("id")
		} else {
			id = ID()
		}
		assignment := core.NewObject("id", id, "tenantId", tenantID, "uniqueKey", uniqueKey, "appId", app.Get("id"),
			"subjectType", subjectType, "subjectId", subjectID, "assignedBy", call.Principal.Identity.Get("id"), "assignedAt", float64(now))
		if !isUndefined(expiresAt) {
			assignment.Set("expiresAt", expiresAt)
		}
		if existing != nil {
			_, err = tx.Put(ctx, "appAssignments", assignment)
		} else {
			_, err = tx.Insert(ctx, "appAssignments", assignment)
		}
		if err != nil {
			return nil, err
		}
		metadata := core.NewObject("key", app.Get("key"), "subjectType", subjectType, "subjectId", subjectID)
		if !isUndefined(expiresAt) {
			metadata.Set("expiresAt", expiresAt)
		}
		if err := api.audit(ctx, tx, call.Principal, "app:assign", tenantID, jsString(app.Get("id")), metadata); err != nil {
			return nil, err
		}
		return assignment, nil
	}, false)
	return Out[apitypes.ApplicationsAssignOutput]{Value: result}, err
}

// Check is POST {basePath}/applications/check. Tells whether a person may use an app, by appId or by the app's
// oauthClientId, for sign-in pages that enforce assignments. An OAuth client with no app in the catalog is not
// governed here (`governed: false`).
func (api *ApplicationsAPI) Check(ctx context.Context, credential core.CredentialInput, input In[apitypes.ApplicationsCheckInput]) (Out[apitypes.ApplicationsCheckOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:applications:read", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		return checkAccess(ctx, api.server, call.Tx, call.Tenant, input.Body)
	}, false)
	return Out[apitypes.ApplicationsCheckOutput]{Value: result}, err
}

// Create is POST {basePath}/applications/create. Registers an app in the tenant's catalog: an OAuth client of this
// deployment, or a link to any tool. Audited as `app:create`.
func (api *ApplicationsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.ApplicationsCreateInput]) (Out[apitypes.ApplicationsCreateOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:applications:manage", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		tenant := jsString(call.Tenant.Get("id"))
		if launchURL := input.Get("launchUrl"); nullish(launchURL) || launchURL == "" {
			return nil, invalidInput("launchUrl is required")
		}
		values, err := appFields(ctx, server, tx, tenant, input.Body, nil)
		if err != nil {
			return nil, err
		}
		existing, err := tx.Find(ctx, "applications", core.NewObject("tenantId", tenant), nil)
		if err != nil {
			return nil, err
		}
		for _, app := range existing {
			if app.Get("uniqueKey") == values.Get("uniqueKey") {
				return nil, core.NewIamError("CONFLICT", "An app with this key exists", 409)
			}
		}
		if len(existing) >= maxApps {
			return nil, core.NewIamError("LIMIT_EXCEEDED", fmt.Sprintf("At most %d apps", maxApps), 409)
		}
		now := float64(server.Now())
		app, err := tx.Insert(ctx, "applications", values.Spread(core.NewObject("id", ID(), "tenantId", tenant, "createdAt", now, "updatedAt", now)))
		if err != nil {
			return nil, err
		}
		metadata := core.NewObject("key", app.Get("key")).Assign(appState(app))
		if err := api.audit(ctx, tx, call.Principal, "app:create", tenant, jsString(app.Get("id")), metadata); err != nil {
			return nil, err
		}
		return app, nil
	}, false)
	return Out[apitypes.ApplicationsCreateOutput]{Value: result}, err
}

// Delete is POST {basePath}/applications/delete. Deletes an app with its assignments and launch history. An app
// that governs an OAuth client needs `releaseClient: true`: afterwards everyone of the organization may sign in to
// that client (disable the app to keep refusing). Audited as `app:delete`.
func (api *ApplicationsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.ApplicationsDeleteInput]) (Out[apitypes.ApplicationsDeleteOutput], error) {
	appID, err := Text(input.Get("appId"), "appId")
	if err != nil {
		return Out[apitypes.ApplicationsDeleteOutput]{}, err
	}
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:applications:manage", appID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		tenantID := jsString(call.Tenant.Get("id"))
		app, err := server.Scoped(ctx, tx, "applications", input.Get("appId"), tenantID)
		if err != nil {
			return nil, err
		}
		if err := assertReleased(app, input.Get("releaseClient")); err != nil {
			return nil, err
		}
		for _, collection := range []string{"appAssignments", "appLaunches"} {
			rows, err := tx.Find(ctx, collection, core.NewObject("tenantId", tenantID, "appId", app.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			for _, row := range rows {
				if err := tx.Delete(ctx, collection, jsString(row.Get("id"))); err != nil {
					return nil, err
				}
			}
		}
		if err := tx.Delete(ctx, "applications", jsString(app.Get("id"))); err != nil {
			return nil, err
		}
		metadata := core.NewObject("key", app.Get("key")).Assign(appState(app))
		if err := api.audit(ctx, tx, call.Principal, "app:delete", tenantID, jsString(app.Get("id")), metadata); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	}, false)
	return Out[apitypes.ApplicationsDeleteOutput]{Value: result}, err
}

// Launch is POST {basePath}/applications/launch. Opens an app the caller has: records the launch (audited as
// `app:launch`) and returns the app's launch URL. Refused while an administrator views as the person
// (`IMPERSONATION_RESTRICTED`).
func (api *ApplicationsAPI) Launch(ctx context.Context, credential core.CredentialInput, input In[apitypes.ApplicationsLaunchInput]) (Out[apitypes.ApplicationsLaunchOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.ApplicationsLaunchOutput]{}, err
	}
	appID, err := Text(input.Get("appId"), "appId")
	if err != nil {
		return Out[apitypes.ApplicationsLaunchOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.ApplicationsLaunchOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if err := selfSession(principal, tenantID); err != nil {
			return nil, err
		}
		if truthy(principal.Session.Get("impersonatorId")) {
			return nil, core.NewIamError("IMPERSONATION_RESTRICTED", "Apps cannot be launched while viewing as someone else", 403)
		}
		mine, err := AppsFor(ctx, server, tx, principal.Identity, server.Now())
		if err != nil {
			return nil, err
		}
		entry, ok := mine[appID]
		if !ok {
			return nil, core.NewIamError("ACCESS_DENIED", "This app is not assigned to you", 403)
		}
		app := entry.Get("app").(*core.Object)
		now := float64(server.Now())
		identityID := principal.Identity.Get("id")
		uniqueKey := appID + ":" + jsString(identityID)
		found, err := tx.Find(ctx, "appLaunches", core.NewObject("tenantId", tenantID, "uniqueKey", uniqueKey), nil)
		if err != nil {
			return nil, err
		}
		var previous *core.Object
		if len(found) > 0 {
			previous = found[0]
		}
		var id any = ID()
		firstAt := any(now)
		count := 1.0
		if previous != nil {
			id = previous.Get("id")
			firstAt = coalesce(previous.Get("firstAt"), now)
			count = jsNumber(coalesce(previous.Get("count"), 0.0)) + 1
		}
		launch := core.NewObject("id", id, "tenantId", tenantID, "uniqueKey", uniqueKey, "appId", appID,
			"identityId", identityID, "firstAt", firstAt, "lastAt", now, "count", count)
		if previous != nil {
			_, err = tx.Put(ctx, "appLaunches", launch)
		} else {
			_, err = tx.Insert(ctx, "appLaunches", launch)
		}
		if err != nil {
			return nil, err
		}
		if err := api.audit(ctx, tx, principal, "app:launch", tenantID, appID, core.NewObject("key", app.Get("key"))); err != nil {
			return nil, err
		}
		return core.NewObject("url", app.Get("launchUrl")), nil
	})
	return Out[apitypes.ApplicationsLaunchOutput]{Value: result}, err
}

// sortByName sorts records by their name (String.prototype.localeCompare), stably.
func sortByName(records []*core.Object) {
	sort.SliceStable(records, func(i, j int) bool {
		return localeCompare(jsString(records[i].Get("name")), jsString(records[j].Get("name"))) < 0
	})
}

// List is POST {basePath}/applications/list. Lists every app of the tenant by name, with how many live assignments
// each has and how many people opened it recently.
func (api *ApplicationsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.ApplicationsListInput]) (Out[apitypes.ApplicationsListOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:applications:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		tx := call.Tx
		tenant := call.Tenant.Get("id")
		now := server.Now()
		assignments, err := tx.Find(ctx, "appAssignments", core.NewObject("tenantId", tenant), nil)
		if err != nil {
			return nil, err
		}
		launches, err := tx.Find(ctx, "appLaunches", core.NewObject("tenantId", tenant), nil)
		if err != nil {
			return nil, err
		}
		apps, err := tx.Find(ctx, "applications", core.NewObject("tenantId", tenant), nil)
		if err != nil {
			return nil, err
		}
		sortByName(apps)
		result := []any{}
		for _, app := range apps {
			assigned, launched := 0, 0
			for _, assignment := range assignments {
				if strictEquals(assignment.Get("appId"), app.Get("id")) && appLive(assignment.Get("expiresAt"), now) {
					assigned++
				}
			}
			for _, launch := range launches {
				if strictEquals(launch.Get("appId"), app.Get("id")) && jsNumber(launch.Get("lastAt")) > float64(now-30*appDayMs) {
					launched++
				}
			}
			result = append(result, app.Spread(core.NewObject("assignments", assigned, "launchedLast30Days", launched)))
		}
		return result, nil
	}, false)
	return Out[apitypes.ApplicationsListOutput]{Value: result}, err
}

// ListAssignments is POST {basePath}/applications/listAssignments. Lists an app's assignments, or every app's when
// appId is left out (one call for a catalog page), with who they name and when each person last opened the app.
func (api *ApplicationsAPI) ListAssignments(ctx context.Context, credential core.CredentialInput, input In[apitypes.ApplicationsListAssignmentsInput]) (Out[apitypes.ApplicationsListAssignmentsOutput], error) {
	server := api.server
	resourceID := jsString(input.Get("tenantId"))
	if !isUndefined(input.Get("appId")) {
		appID, err := Text(input.Get("appId"), "appId")
		if err != nil {
			return Out[apitypes.ApplicationsListAssignmentsOutput]{}, err
		}
		resourceID = appID
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:applications:read", resourceID, func(ctx context.Context, call MutationContext) ([]any, error) {
		tx := call.Tx
		tenantID := jsString(call.Tenant.Get("id"))
		filter := core.NewObject("tenantId", tenantID)
		if !isUndefined(input.Get("appId")) {
			app, err := server.Scoped(ctx, tx, "applications", input.Get("appId"), tenantID)
			if err != nil {
				return nil, err
			}
			filter.Set("appId", app.Get("id"))
		}
		found, err := tx.Find(ctx, "appLaunches", filter, nil)
		if err != nil {
			return nil, err
		}
		launches := map[string]any{}
		for _, launch := range found {
			launches[jsString(launch.Get("appId"))+":"+jsString(launch.Get("identityId"))] = launch.Get("lastAt")
		}
		names, err := api.directory(ctx, tx, call.Principal, tenantID)
		if err != nil {
			return nil, err
		}
		assignments, err := tx.Find(ctx, "appAssignments", filter, nil)
		if err != nil {
			return nil, err
		}
		type view struct {
			record *core.Object
			label  string
		}
		views := []view{}
		for _, assignment := range assignments {
			var subjectName any = core.Undefined
			if assignment.Get("subjectType") == "group" {
				group, err := tx.Get(ctx, "groups", jsString(assignment.Get("subjectId")))
				if err != nil {
					return nil, err
				}
				subjectName = member(group, "name")
			} else if names {
				identity, err := tx.Get(ctx, "identities", jsString(assignment.Get("subjectId")))
				if err != nil {
					return nil, err
				}
				subjectName = coalesce(member(identity, "email"), member(identity, "name"))
			}
			var lastLaunchedAt any = core.Undefined
			if assignment.Get("subjectType") == "identity" {
				if last, ok := launches[jsString(assignment.Get("appId"))+":"+jsString(assignment.Get("subjectId"))]; ok {
					lastLaunchedAt = last
				}
			}
			record := assignment.Spread()
			if truthy(subjectName) {
				record.Set("subjectName", subjectName)
			}
			if !isUndefined(lastLaunchedAt) {
				record.Set("lastLaunchedAt", lastLaunchedAt)
			}
			views = append(views, view{record: record, label: jsString(coalesce(record.Get("subjectName"), record.Get("subjectId")))})
		}
		sort.SliceStable(views, func(i, j int) bool { return localeCompare(views[i].label, views[j].label) < 0 })
		result := make([]any, len(views))
		for index, item := range views {
			result[index] = item.record
		}
		return result, nil
	}, false)
	return Out[apitypes.ApplicationsListAssignmentsOutput]{Value: result}, err
}

// Mine is POST {basePath}/applications/mine. Returns the caller's launcher: the apps they may launch now (with when
// they last did), and the apps they could request through an access package. Needs only a signed-in session of the
// organization.
func (api *ApplicationsAPI) Mine(ctx context.Context, credential core.CredentialInput, input In[apitypes.ApplicationsMineInput]) (Out[apitypes.ApplicationsMineOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.ApplicationsMineOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.ApplicationsMineOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]any, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if err := selfSession(principal, tenantID); err != nil {
			return nil, err
		}
		now := server.Now()
		mine, err := AppsFor(ctx, server, tx, principal.Identity, now)
		if err != nil {
			return nil, err
		}
		found, err := tx.Find(ctx, "appLaunches", core.NewObject("tenantId", tenantID, "identityId", principal.Identity.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		launches := map[string]any{}
		for _, launch := range found {
			launches[jsString(launch.Get("appId"))] = launch.Get("lastAt")
		}
		requestable := map[string]bool{}
		canRequest := func(packageID string) (bool, error) {
			if _, ok := requestable[packageID]; !ok {
				pkg, err := tx.Get(ctx, "accessPackages", packageID)
				if err != nil {
					return false, err
				}
				requestable[packageID] = pkg != nil && pkg.Get("tenantId") == tenantID && truthy(pkg.Get("requestable"))
			}
			return requestable[packageID], nil
		}
		apps, err := tx.Find(ctx, "applications", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		result := []*core.Object{}
		for _, app := range apps {
			if !truthy(app.Get("enabled")) {
				continue
			}
			appID := jsString(app.Get("id"))
			entry, has := mine[appID]
			// A package deleted (or no longer requestable) since it was named is not offered.
			if !has {
				if !truthy(app.Get("requestPackageId")) {
					continue
				}
				allowed, err := canRequest(jsString(app.Get("requestPackageId")))
				if err != nil {
					return nil, err
				}
				if !allowed {
					continue
				}
			}
			item := core.NewObject("id", app.Get("id"), "key", app.Get("key"), "name", app.Get("name"))
			for _, key := range []string{"description", "category", "logoUrl"} {
				if truthy(app.Get(key)) {
					item.Set(key, app.Get(key))
				}
			}
			if has {
				item.Set("via", entry.Get("via"))
			} else {
				item.Set("requestPackageId", app.Get("requestPackageId"))
			}
			if last, ok := launches[appID]; ok {
				item.Set("lastLaunchedAt", last)
			}
			result = append(result, item)
		}
		sort.SliceStable(result, func(i, j int) bool {
			a, b := result[i], result[j]
			requestA, requestB := truthy(a.Get("requestPackageId")), truthy(b.Get("requestPackageId"))
			if requestA != requestB {
				return !requestA
			}
			lastA, lastB := jsNumber(coalesce(a.Get("lastLaunchedAt"), 0.0)), jsNumber(coalesce(b.Get("lastLaunchedAt"), 0.0))
			if difference := lastB - lastA; difference != 0 && !math.IsNaN(difference) {
				return difference < 0
			}
			return localeCompare(jsString(a.Get("name")), jsString(b.Get("name"))) < 0
		})
		out := make([]any, len(result))
		for index, item := range result {
			out[index] = item
		}
		return out, nil
	})
	return Out[apitypes.ApplicationsMineOutput]{Value: result}, err
}

// RemoveUnused is POST {basePath}/applications/removeUnused. Removes an app's direct assignments to people who have
// not opened it for unusedDays (group assignments stay). Audited as `app:unassign`.
func (api *ApplicationsAPI) RemoveUnused(ctx context.Context, credential core.CredentialInput, input In[apitypes.ApplicationsRemoveUnusedInput]) (Out[apitypes.ApplicationsRemoveUnusedOutput], error) {
	appID, err := Text(input.Get("appId"), "appId")
	if err != nil {
		return Out[apitypes.ApplicationsRemoveUnusedOutput]{}, err
	}
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:applications:assign", appID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		tenantID := jsString(call.Tenant.Get("id"))
		app, err := server.Scoped(ctx, tx, "applications", input.Get("appId"), tenantID)
		if err != nil {
			return nil, err
		}
		days, err := Integer(input.Get("unusedDays"), "unusedDays", 7, 3650)
		if err != nil {
			return nil, err
		}
		assignments, err := tx.Find(ctx, "appAssignments", core.NewObject("tenantId", tenantID, "appId", app.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		launches, err := tx.Find(ctx, "appLaunches", core.NewObject("tenantId", tenantID, "appId", app.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		unused := unusedAssignments(assignments, launches, server.Now(), days)
		for _, assignment := range unused {
			if err := tx.Delete(ctx, "appAssignments", jsString(assignment.Get("id"))); err != nil {
				return nil, err
			}
			metadata := core.NewObject("subjectType", "identity", "subjectId", assignment.Get("subjectId"),
				"reason", "unused "+core.NumberString(days)+" days")
			if err := api.audit(ctx, tx, call.Principal, "app:unassign", tenantID, jsString(app.Get("id")), metadata); err != nil {
				return nil, err
			}
		}
		return core.NewObject("removed", len(unused)), nil
	}, false)
	return Out[apitypes.ApplicationsRemoveUnusedOutput]{Value: result}, err
}

// Unassign is POST {basePath}/applications/unassign. Removes one assignment of an app; authorized on its app, like
// assign. Audited as `app:unassign`.
func (api *ApplicationsAPI) Unassign(ctx context.Context, credential core.CredentialInput, input In[apitypes.ApplicationsUnassignInput]) (Out[apitypes.ApplicationsUnassignOutput], error) {
	server := api.server
	assignmentID, err := Text(input.Get("assignmentId"), "assignmentId")
	if err != nil {
		return Out[apitypes.ApplicationsUnassignOutput]{}, err
	}
	// Authorized on the assignment's app (per-app administrators), or on the ID itself when there is no such record.
	found, err := server.Store.Get(ctx, "appAssignments", assignmentID)
	if err != nil {
		return Out[apitypes.ApplicationsUnassignOutput]{}, err
	}
	resourceID := assignmentID
	if found != nil && strictEquals(found.Get("tenantId"), input.Get("tenantId")) {
		resourceID = jsString(found.Get("appId"))
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:applications:assign", resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		tenantID := jsString(call.Tenant.Get("id"))
		assignment, err := server.Scoped(ctx, tx, "appAssignments", assignmentID, tenantID)
		if err != nil {
			return nil, err
		}
		if assignment.Get("appId") != resourceID {
			return nil, core.NewIamError("CONFLICT", "The assignment changed; try again", 409)
		}
		if err := tx.Delete(ctx, "appAssignments", jsString(assignment.Get("id"))); err != nil {
			return nil, err
		}
		metadata := core.NewObject("subjectType", assignment.Get("subjectType"), "subjectId", assignment.Get("subjectId"))
		if err := api.audit(ctx, tx, call.Principal, "app:unassign", tenantID, jsString(assignment.Get("appId")), metadata); err != nil {
			return nil, err
		}
		return core.NewObject("removed", true), nil
	}, false)
	return Out[apitypes.ApplicationsUnassignOutput]{Value: result}, err
}

// Update is POST {basePath}/applications/update. Changes an app's name, URLs, client, visibility, request package,
// owners, or whether it is enabled. Clearing `oauthClientId` needs `releaseClient: true` (the client stops being
// governed). Audited as `app:update` with the state before and after.
func (api *ApplicationsAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.ApplicationsUpdateInput]) (Out[apitypes.ApplicationsUpdateOutput], error) {
	appID, err := Text(input.Get("appId"), "appId")
	if err != nil {
		return Out[apitypes.ApplicationsUpdateOutput]{}, err
	}
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:applications:manage", appID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		tenantID := jsString(call.Tenant.Get("id"))
		previous, err := server.Scoped(ctx, tx, "applications", input.Get("appId"), tenantID)
		if err != nil {
			return nil, err
		}
		values, err := appFields(ctx, server, tx, tenantID, input.Body, previous)
		if err != nil {
			return nil, err
		}
		if truthy(previous.Get("oauthClientId")) && !strictEquals(values.Get("oauthClientId"), previous.Get("oauthClientId")) {
			if err := assertReleased(previous, input.Get("releaseClient")); err != nil {
				return nil, err
			}
		}
		kept := previous.Spread()
		for _, key := range []string{"description", "category", "logoUrl", "oauthClientId", "requestPackageId"} {
			kept.Delete(key)
		}
		app, err := tx.Put(ctx, "applications", kept.Assign(values, core.NewObject("updatedAt", float64(server.Now()))))
		if err != nil {
			return nil, err
		}
		metadata := core.NewObject("key", app.Get("key"), "before", appState(previous), "after", appState(app))
		if err := api.audit(ctx, tx, call.Principal, "app:update", tenantID, jsString(app.Get("id")), metadata); err != nil {
			return nil, err
		}
		return app, nil
	}, false)
	return Out[apitypes.ApplicationsUpdateOutput]{Value: result}, err
}

// Usage is POST {basePath}/applications/usage. Assignment hygiene: per app, how many people have it, how many
// launched it in 30 days, and the direct assignments unused for unusedDays (default 90).
func (api *ApplicationsAPI) Usage(ctx context.Context, credential core.CredentialInput, input In[apitypes.ApplicationsUsageInput]) (Out[apitypes.ApplicationsUsageOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:applications:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		tenant := jsString(call.Tenant.Get("id"))
		unusedDays, err := Integer(coalesce(input.Get("unusedDays"), 90.0), "unusedDays", 1, 3650)
		if err != nil {
			return nil, err
		}
		withNames, err := api.directory(ctx, call.Tx, call.Principal, tenant)
		if err != nil {
			return nil, err
		}
		return usageOf(ctx, server, call.Tx, tenant, unusedDays, withNames)
	}, false)
	return Out[apitypes.ApplicationsUsageOutput]{Value: result}, err
}

// checkAccess is api/applications.ts checkAccess: exactly one of appId or oauthClientId names the app.
func checkAccess(ctx context.Context, server *ServerContext, tx core.IamStore, tenant *core.Object, input *core.Object) (*core.Object, error) {
	if input == nil {
		input = core.NewObject()
	}
	if isUndefined(input.Get("appId")) == isUndefined(input.Get("oauthClientId")) {
		return nil, invalidInput("Name exactly one of appId or oauthClientId")
	}
	identityID, err := Text(input.Get("identityId"), "identityId")
	if err != nil {
		return nil, err
	}
	var target *core.Object
	if !isUndefined(input.Get("appId")) {
		appID, err := Text(input.Get("appId"), "appId")
		if err != nil {
			return nil, err
		}
		target = core.NewObject("appId", appID)
	} else {
		clientID, err := Text(input.Get("oauthClientId"), "oauthClientId", 256)
		if err != nil {
			return nil, err
		}
		target = core.NewObject("oauthClientId", clientID)
	}
	return AppAccess(ctx, server, tx, tenant, identityID, target)
}

// unusedAssignments is api/applications.ts unusedAssignments: direct assignments made at least `days` ago whose
// person has not launched the app within `days`.
func unusedAssignments(assignments, launches []*core.Object, now int64, days float64) []*core.Object {
	cutoff := float64(now) - days*appDayMs
	last := map[string]any{}
	for _, launch := range launches {
		last[jsString(launch.Get("appId"))+":"+jsString(launch.Get("identityId"))] = launch.Get("lastAt")
	}
	result := []*core.Object{}
	for _, assignment := range assignments {
		lastAt, ok := last[jsString(assignment.Get("appId"))+":"+jsString(assignment.Get("subjectId"))]
		if !ok || nullish(lastAt) {
			lastAt = 0.0
		}
		if assignment.Get("subjectType") == "identity" && jsNumber(assignment.Get("assignedAt")) <= cutoff && jsNumber(lastAt) <= cutoff {
			result = append(result, assignment)
		}
	}
	return result
}

// usageOf is api/applications.ts usageOf.
func usageOf(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, unusedDays float64, withNames bool) ([]any, error) {
	now := server.Now()
	apps, err := tx.Find(ctx, "applications", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	launches, err := tx.Find(ctx, "appLaunches", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	assignments, err := tx.Find(ctx, "appAssignments", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	holders, err := AppHolders(ctx, server, tx, tenantID, now)
	if err != nil {
		return nil, err
	}
	names := map[string]any{}
	if withNames {
		identities, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		for _, identity := range identities {
			names[jsString(identity.Get("id"))] = coalesce(identity.Get("email"), identity.Get("name"))
		}
	}
	lastLaunch := map[string]any{}
	for _, launch := range launches {
		lastLaunch[jsString(launch.Get("appId"))+":"+jsString(launch.Get("identityId"))] = launch.Get("lastAt")
	}
	sortByName(apps)
	result := []any{}
	for _, app := range apps {
		appID := jsString(app.Get("id"))
		launched := 0
		var appLaunches, appAssignments []*core.Object
		for _, launch := range launches {
			if strictEquals(launch.Get("appId"), app.Get("id")) {
				appLaunches = append(appLaunches, launch)
				if jsNumber(launch.Get("lastAt")) > float64(now-30*appDayMs) {
					launched++
				}
			}
		}
		for _, assignment := range assignments {
			if strictEquals(assignment.Get("appId"), app.Get("id")) {
				appAssignments = append(appAssignments, assignment)
			}
		}
		unused := []any{}
		for _, assignment := range unusedAssignments(appAssignments, appLaunches, now, unusedDays) {
			subjectID := jsString(assignment.Get("subjectId"))
			entry := core.NewObject("assignmentId", assignment.Get("id"), "identityId", assignment.Get("subjectId"))
			if name, ok := names[subjectID]; ok && truthy(name) {
				entry.Set("name", name)
			}
			if last, ok := lastLaunch[appID+":"+subjectID]; ok && !isUndefined(last) {
				entry.Set("lastLaunchedAt", last)
			}
			unused = append(unused, entry)
		}
		people := holders[appID]
		result = append(result, core.NewObject("appId", app.Get("id"), "key", app.Get("key"), "name", app.Get("name"),
			"people", people, "launchedLast30Days", launched, "unused", unused))
	}
	return result, nil
}

// ApplicationsRuntime is api/applications.ts createApplicationsRuntime(): the catalog for the deployment's own code
// (`iam.applications`), an unaudited access check for sign-in pages.
type ApplicationsRuntime struct {
	server *ServerContext
}

// Allowed (api/applications.ts createApplicationsRuntime().allowed): Whether `identityId` may use the app registered
// for `oauthClientId` (or `appId`). The built-in OAuth provider already enforces this for catalog clients; call it
// from other sign-in or consent pages. Ungoverned clients are allowed.
func (s *ApplicationsRuntime) Allowed(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	if input == nil {
		input = core.NewObject()
	}
	return core.Transact(ctx, s.server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		tenantID, err := Text(input.Get("tenantId"), "tenantId")
		if err != nil {
			return nil, err
		}
		tenant, err := s.server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		return checkAccess(ctx, s.server, tx, tenant, input)
	})
}

// CreateApplicationsRuntime builds the ApplicationsRuntime (api/applications.ts createApplicationsRuntime).
func CreateApplicationsRuntime(server *ServerContext) *ApplicationsRuntime {
	return &ApplicationsRuntime{server: server}
}
