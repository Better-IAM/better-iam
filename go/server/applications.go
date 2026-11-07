package server

// Port of packages/server/src/applications.ts: the application catalog behind the "My apps" launcher. The tenant's
// applications (OpenID Connect clients of this deployment, or plain links to other tools), who may see and launch
// each one (everyone, or assigned people and groups), launch history, and the access package people request to get an
// app. For an OpenID Connect app the assignment is enforced: the OAuth provider refuses to issue or refresh tokens for
// people without the app (`iam.protocolHost.clientAllowed`).
//
// Records: `applications` (uniqueKey `key:{key}`), `appAssignments` (uniqueKey `{appId}:{subjectType}:{subjectId}`)
// and `appLaunches` (uniqueKey `{appId}:{identityId}`).

import (
	"context"
	"regexp"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

var appKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

// AppKey (applications.ts appKey) validates an app key: lowercase letters, digits, dots, underscores or hyphens,
// starting with a letter, at most 64 characters.
func AppKey(value any) (result string, err error) {
	key, err := Text(value, "key", 64)
	if err != nil {
		return "", err
	}
	if !appKeyPattern.MatchString(key) {
		return "", invalidInput("App keys use lowercase letters, digits, dots, underscores or hyphens")
	}
	return key, nil
}

// appLocalHosts is applications.ts localHosts.
var appLocalHosts = map[string]bool{"localhost": true, "127.0.0.1": true, "[::1]": true}

// LocalDeployment (applications.ts localDeployment): Whether the deployment itself runs on the local machine
// (development), where apps may use plain http locally. An empty baseURL stands for undefined.
func LocalDeployment(baseURL string) (result bool, err error) {
	if baseURL == "" {
		return false, nil
	}
	u, parseErr := auth.ParseFetchURL(baseURL)
	if parseErr != nil {
		return false, nil
	}
	return appLocalHosts[u.Hostname], nil
}

// AppURL (applications.ts appUrl): Launch and logo URLs: https, or http on the local machine when the deployment
// itself is local (development).
func AppURL(value any, name string, allowLocal bool) (result string, err error) {
	raw, err := Text(value, name, 2048)
	if err != nil {
		return "", err
	}
	u, parseErr := auth.ParseFetchURL(raw)
	if parseErr != nil {
		return "", invalidInput(name + " must be an absolute URL")
	}
	local := allowLocal && appLocalHosts[u.Hostname]
	if u.Protocol != "https:" && !(u.Protocol == "http:" && local) {
		return "", invalidInput(name + " must use https")
	}
	if urlUsername(u) != "" || urlPassword(u) != "" {
		return "", invalidInput(name + " cannot carry credentials")
	}
	return u.Href, nil
}

// appLive is applications.ts live: no end, or an end after now.
func appLive(expiresAt any, now int64) bool {
	if isUndefined(expiresAt) {
		return true
	}
	return jsNumber(expiresAt) > float64(now)
}

// appEligible is applications.ts eligible: whether an identity may hold apps at all (an active, unexpired person).
func appEligible(server *ServerContext, identity *core.Object) bool {
	return identity.Get("kind") == "user" && identity.Get("status") == "active" && !server.IdentityExpired(identity)
}

// appEntry is one launcher entry of AppsFor: `{ app, via }`.
func appEntry(app *core.Object, via string) *core.Object {
	return core.NewObject("app", app, "via", via)
}

// AppsFor (applications.ts appsFor): Which enabled apps a person may launch right now: everyone apps, apps assigned
// to them, and apps assigned to a group they belong to (memberships and assignments that have not ended). Only
// active, unexpired people have apps. Each entry is `{ app, via }` keyed by the app's ID; via is `everyone`,
// `direct` or `group`.
func AppsFor(ctx context.Context, server *ServerContext, tx core.IamStore, identity *core.Object, now int64) (result map[string]*core.Object, err error) {
	result = map[string]*core.Object{}
	if !appEligible(server, identity) {
		return result, nil
	}
	tenantID := identity.Get("tenantId")
	found, err := tx.Find(ctx, "applications", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	apps := map[string]*core.Object{}
	var order []string
	for _, app := range found {
		if !truthy(app.Get("enabled")) {
			continue
		}
		id := jsString(app.Get("id"))
		if _, seen := apps[id]; !seen {
			order = append(order, id)
		}
		apps[id] = app
	}
	if len(apps) == 0 {
		return result, nil
	}
	for _, id := range order {
		app := apps[id]
		if app.Get("visibility") == "everyone" {
			result[id] = appEntry(app, "everyone")
		}
	}
	members, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "identityId", identity.Get("id")), nil)
	if err != nil {
		return nil, err
	}
	groups := newOrderedSet()
	for _, member := range members {
		if appLive(member.Get("expiresAt"), now) {
			groups.Add(jsString(member.Get("groupId")))
		}
	}
	// Only this person's and their groups' assignments (`subjectId` is indexed), never the whole tenant's.
	assignments, err := tx.Find(ctx, "appAssignments", core.NewObject("tenantId", tenantID, "subjectType", "identity", "subjectId", identity.Get("id")), nil)
	if err != nil {
		return nil, err
	}
	for _, groupID := range groups.Values() {
		found, err := tx.Find(ctx, "appAssignments", core.NewObject("tenantId", tenantID, "subjectType", "group", "subjectId", groupID), nil)
		if err != nil {
			return nil, err
		}
		assignments = append(assignments, found...)
	}
	for _, assignment := range assignments {
		app, ok := apps[jsString(assignment.Get("appId"))]
		if !ok || !appLive(assignment.Get("expiresAt"), now) {
			continue
		}
		direct := assignment.Get("subjectType") == "identity"
		id := jsString(app.Get("id"))
		previous, has := result[id]
		if !has || previous.Get("via") == "everyone" || (previous.Get("via") == "group" && direct) {
			via := "group"
			if direct {
				via = "direct"
			}
			result[id] = appEntry(app, via)
		}
	}
	return result, nil
}

// AppHolders (applications.ts appHolders): How many people hold each app now, in one pass over the tenant (for usage
// reports): everyone apps count every eligible person, assigned apps the union of direct assignees and live members
// of assigned groups.
func AppHolders(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, now int64) (result map[string]float64, err error) {
	identities, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	people := newOrderedSet()
	for _, identity := range identities {
		if appEligible(server, identity) {
			people.Add(jsString(identity.Get("id")))
		}
	}
	groupMembers, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	members := map[string][]string{}
	for _, member := range groupMembers {
		identityID := jsString(member.Get("identityId"))
		if appLive(member.Get("expiresAt"), now) && people.Has(identityID) {
			groupID := jsString(member.Get("groupId"))
			members[groupID] = append(members[groupID], identityID)
		}
	}
	assignments, err := tx.Find(ctx, "appAssignments", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	holders := map[string]*orderedSet{}
	for _, assignment := range assignments {
		if !appLive(assignment.Get("expiresAt"), now) {
			continue
		}
		appID := jsString(assignment.Get("appId"))
		set, ok := holders[appID]
		if !ok {
			set = newOrderedSet()
		}
		subjectID := jsString(assignment.Get("subjectId"))
		if assignment.Get("subjectType") == "identity" {
			if people.Has(subjectID) {
				set.Add(subjectID)
			}
		} else {
			for _, identityID := range members[subjectID] {
				set.Add(identityID)
			}
		}
		holders[appID] = set
	}
	apps, err := tx.Find(ctx, "applications", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	result = map[string]float64{}
	for _, app := range apps {
		id := jsString(app.Get("id"))
		switch {
		case !truthy(app.Get("enabled")):
			result[id] = 0
		case app.Get("visibility") == "everyone":
			result[id] = float64(people.Len())
		default:
			count := 0
			if set, ok := holders[id]; ok {
				count = set.Len()
			}
			result[id] = float64(count)
		}
	}
	return result, nil
}

// AppAccess (applications.ts appAccess): Whether a person may use an app, by its ID or its OAuth client: `governed:
// false` when no app in the catalog names the client (nothing to enforce). Refuses people of another tenant, an
// inactive tenant, and people who are not active. target is `{ appId }` or `{ oauthClientId }`.
func AppAccess(ctx context.Context, server *ServerContext, tx core.IamStore, tenant *core.Object, identityID string, target *core.Object) (result *core.Object, err error) {
	apps, err := tx.Find(ctx, "applications", core.NewObject("tenantId", tenant.Get("id")), nil)
	if err != nil {
		return nil, err
	}
	byID := target.Has("appId")
	var app *core.Object
	for _, item := range apps {
		if (byID && item.Get("id") == target.Get("appId")) || (!byID && item.Get("oauthClientId") == target.Get("oauthClientId")) {
			app = item
			break
		}
	}
	if app == nil {
		if byID {
			return nil, core.NewIamError("NOT_FOUND", "App not found", 404)
		}
		return core.NewObject("allowed", true, "governed", false), nil
	}
	identity, err := tx.Get(ctx, "identities", identityID)
	if err != nil {
		return nil, err
	}
	if identity == nil || identity.Get("tenantId") != tenant.Get("id") || tenant.Get("status") != "active" {
		return core.NewObject("allowed", false, "governed", true, "appId", app.Get("id")), nil
	}
	mine, err := AppsFor(ctx, server, tx, identity, server.Now())
	if err != nil {
		return nil, err
	}
	_, allowed := mine[jsString(app.Get("id"))]
	return core.NewObject("allowed", allowed, "governed", true, "appId", app.Get("id")), nil
}

// AppClientAllowed (applications.ts appClientAllowed): The OAuth provider's gate (`protocolHost.clientAllowed`): may
// this person get tokens for this client?
func AppClientAllowed(ctx context.Context, server *ServerContext, identityID string, tenantID string, clientID string) (result bool, err error) {
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (bool, error) {
		tenant, err := tx.Get(ctx, "tenants", tenantID)
		if err != nil {
			return false, err
		}
		if tenant == nil {
			return false, nil
		}
		access, err := AppAccess(ctx, server, tx, tenant, identityID, core.NewObject("oauthClientId", clientID))
		if err != nil {
			return false, err
		}
		return access.Get("allowed") == true, nil
	})
}

// ReleaseAppRecordsOf (applications.ts releaseAppRecordsOf): When a person is deleted: their assignments and launch
// history go, and they stop being an app owner.
func ReleaseAppRecordsOf(ctx context.Context, tx core.IamStore, identity *core.Object) (err error) {
	tenantID := identity.Get("tenantId")
	identityID := identity.Get("id")
	assignments, err := tx.Find(ctx, "appAssignments", core.NewObject("tenantId", tenantID, "subjectType", "identity", "subjectId", identityID), nil)
	if err != nil {
		return err
	}
	for _, assignment := range assignments {
		if err := tx.Delete(ctx, "appAssignments", jsString(assignment.Get("id"))); err != nil {
			return err
		}
	}
	launches, err := tx.Find(ctx, "appLaunches", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return err
	}
	for _, launch := range launches {
		if err := tx.Delete(ctx, "appLaunches", jsString(launch.Get("id"))); err != nil {
			return err
		}
	}
	apps, err := tx.Find(ctx, "applications", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return err
	}
	for _, app := range apps {
		owners, _ := app.Get("ownerIds").([]any)
		includes := false
		kept := []any{}
		for _, ownerID := range owners {
			if ownerID == identityID {
				includes = true
				continue
			}
			kept = append(kept, ownerID)
		}
		if includes {
			if _, err := tx.Put(ctx, "applications", app.Spread(core.NewObject("ownerIds", kept))); err != nil {
				return err
			}
		}
	}
	return nil
}

// ReleaseGroupApps (applications.ts releaseGroupApps): When a group is deleted: its app assignments go with it.
func ReleaseGroupApps(ctx context.Context, tx core.IamStore, tenantID string, groupID string) (err error) {
	assignments, err := tx.Find(ctx, "appAssignments", core.NewObject("tenantId", tenantID, "subjectType", "group", "subjectId", groupID), nil)
	if err != nil {
		return err
	}
	for _, assignment := range assignments {
		if err := tx.Delete(ctx, "appAssignments", jsString(assignment.Get("id"))); err != nil {
			return err
		}
	}
	return nil
}
