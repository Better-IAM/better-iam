package server

// Port of packages/server/src/api/identities.ts: the `identities` API group (people and service accounts of a
// tenant: provisioning, profile, status, ownership, sessions, linked external sign-ins, member invitations, data
// export, impersonation and offboarding) and the helpers other modules share (deleteIdentity, assertOwnerControl,
// revokeInvitationsBy).

import (
	"context"
	"sort"
	"strings"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// IdentitiesAPI is the `identities` API group (packages/server/src/api/identities.ts createIdentitiesApi): every method runs through the
// operation envelope; the router maps POST {basePath}/identities/{method} onto it.
type IdentitiesAPI struct {
	server *ServerContext
}

// CreateIdentitiesAPI builds the `identities` API group.
func CreateIdentitiesAPI(server *ServerContext) *IdentitiesAPI {
	return &IdentitiesAPI{server: server}
}

// identitySeatsMessage is the refusal of `createMany` and `invite` when a group they fill carries license seats
// (groups.ts).
const identitySeatsMessage = "A group you add people to carries license seats; adding them needs iam:licenses:assign"

// identityFlag is an optional boolean input (false when absent).
func identityFlag(value any, name string) (bool, error) {
	if isUndefined(value) {
		return false, nil
	}
	b, ok := value.(bool)
	if !ok {
		return false, invalidInput(name + " must be a boolean")
	}
	return b, nil
}

// providerLink is an external sign-in an administrator links to an account ahead of its first federated sign-in.
type providerLink struct {
	// ProviderID is the connection's provider key: an OAuth connection's `id`, a SAML connection's `providerId`.
	ProviderID string
	// Issuer is the IdP's issuer exactly as the protocol reports it (OIDC `iss`, SAML IdP entity ID).
	Issuer string
	// Subject is the person's stable ID at the IdP (OIDC `sub`, SAML NameID).
	Subject string
}

// identityProviderLinks validates up to 10 links per person, each a distinct provider.
func identityProviderLinks(value any) ([]providerLink, error) {
	if isUndefined(value) {
		return nil, nil
	}
	list, ok := value.([]any)
	if !ok || len(list) > 10 {
		return nil, invalidInput("providers must list at most 10 external sign-ins")
	}
	links := make([]providerLink, 0, len(list))
	seen := map[string]bool{}
	for _, item := range list {
		link, err := identityProviderLinkInput(item)
		if err != nil {
			return nil, err
		}
		links = append(links, link)
		seen[link.ProviderID] = true
	}
	if len(seen) != len(links) {
		return nil, invalidInput("providers must name each provider once")
	}
	return links, nil
}

func identityProviderLinkInput(value any) (providerLink, error) {
	link, err := Object(value)
	if err != nil {
		return providerLink{}, err
	}
	providerID, err := Text(link.Get("providerId"), "providerId", 256)
	if err != nil {
		return providerLink{}, err
	}
	issuer, err := Text(link.Get("issuer"), "issuer", 1024)
	if err != nil {
		return providerLink{}, err
	}
	subject, err := Text(link.Get("subject"), "subject", 512)
	if err != nil {
		return providerLink{}, err
	}
	return providerLink{ProviderID: providerID, Issuer: issuer, Subject: subject}, nil
}

// identityProviderLinkView is a linked external sign-in as administrators see it.
func identityProviderLinkView(row *core.Object) *core.Object {
	view := core.NewObject(
		"id", jsString(row.Get("id")),
		"identityId", jsString(row.Get("identityId")),
		"providerId", jsString(row.Get("providerId")),
		"issuer", jsString(row.Get("issuer")),
		"subject", jsString(row.Get("subject")),
	)
	if createdAt, ok := row.Get("createdAt").(float64); ok {
		view.Set("createdAt", createdAt)
	}
	return view
}

// insertIdentityProviderLink records a link the federation callback (federation.ts) finds by `[providerId, issuer,
// subject]`. An external account signs in to one identity only, and an identity has at most one link per provider
// (unlink before relinking).
func insertIdentityProviderLink(ctx context.Context, tx core.IamStore, tenantID, identityID string, link providerLink, now int64) (*core.Object, error) {
	uniqueKey, _, err := core.Stringify([]any{link.ProviderID, link.Issuer, link.Subject})
	if err != nil {
		return nil, err
	}
	taken, err := tx.Find(ctx, "externalIdentities", core.NewObject("tenantId", tenantID, "uniqueKey", uniqueKey), nil)
	if err != nil {
		return nil, err
	}
	if len(taken) > 0 {
		return nil, core.NewIamError("ACCOUNT_LINK_CONFLICT", "External identity is already linked to another account", 409)
	}
	own, err := tx.Find(ctx, "externalIdentities", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return nil, err
	}
	for _, row := range own {
		if row.Get("providerId") == link.ProviderID {
			return nil, core.NewIamError("ACCOUNT_LINK_CONFLICT", "This account is already linked through that provider; unlink it first", 409)
		}
	}
	inserted, err := tx.Insert(ctx, "externalIdentities", core.NewObject(
		"id", ID(),
		"tenantId", tenantID,
		"uniqueKey", uniqueKey,
		"identityId", identityID,
		"providerId", link.ProviderID,
		"issuer", link.Issuer,
		"subject", link.Subject,
		"createdAt", float64(now),
	))
	if err != nil {
		return nil, err
	}
	return identityProviderLinkView(inserted), nil
}

// identityRemove deletes every record of a collection matching the filter.
func identityRemove(ctx context.Context, tx core.IamStore, collection string, filter *core.Object) error {
	rows, err := tx.Find(ctx, collection, filter, nil)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if err := tx.Delete(ctx, collection, jsString(row.Get("id"))); err != nil {
			return err
		}
	}
	return nil
}

// identityLinksOf is the identity links on either side of an identity (left side first).
func identityLinksOf(ctx context.Context, tx core.IamStore, identityID any) ([]*core.Object, error) {
	left, err := tx.Find(ctx, "identityLinks", core.NewObject("leftId", identityID), nil)
	if err != nil {
		return nil, err
	}
	right, err := tx.Find(ctx, "identityLinks", core.NewObject("rightId", identityID), nil)
	if err != nil {
		return nil, err
	}
	return append(left, right...), nil
}

// identityRootProtected refuses a target root administrator unless the caller is a root principal.
func identityRootProtected(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, identity *core.Object) error {
	if !truthy(identity.Get("rootAdmin")) {
		return nil
	}
	root, err := server.RootPrincipal(ctx, tx, principal)
	if err != nil {
		return err
	}
	if !root {
		return core.NewIamError("ACCESS_DENIED", "Root capability is protected", 403)
	}
	return nil
}

// DeleteIdentity (api/identities.ts deleteIdentity): Deletes an identity: every credential, factor, binding,
// membership, boundary, and link is removed or revoked in the same transaction, and a tombstone without email or
// secrets remains so audit records keep a resolvable principal.
func DeleteIdentity(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, identity *core.Object) (result *core.Object, err error) {
	if identity.Get("status") == "deleted" {
		return nil, core.NewIamError("CONFLICT", "Identity is already deleted", 409)
	}
	if core.StrictEquals(identity.Get("id"), principal.Identity.Get("id")) {
		return nil, invalidInput("An identity cannot delete itself")
	}
	if err := identityRootProtected(ctx, server, tx, principal, identity); err != nil {
		return nil, err
	}
	if err := AssertOwnerControl(ctx, server, tx, principal, identity, "Only an owner can delete an owner"); err != nil {
		return nil, err
	}
	if err := server.ProtectLastOwner(ctx, tx, identity); err != nil {
		return nil, err
	}
	// A legal hold (privacy.ts) keeps the person: no deletion path removes what litigation needs kept.
	if err := AssertNoLegalHold(ctx, tx, identity, server.Now()); err != nil {
		return nil, err
	}
	identityID := jsString(identity.Get("id"))
	tenantID := identity.Get("tenantId")
	if err := server.RevokeAll(ctx, tx, identityID); err != nil {
		return nil, err
	}
	if err := RevokeInvitationsBy(ctx, tx, identityID); err != nil {
		return nil, err
	}
	remove := func(collection string, filter *core.Object) error {
		return identityRemove(ctx, tx, collection, filter)
	}
	byIdentity := func() *core.Object { return core.NewObject("tenantId", tenantID, "identityId", identityID) }
	if err := remove("bindings", core.NewObject("tenantId", tenantID, "subjectType", "identity", "subjectId", identityID)); err != nil {
		return nil, err
	}
	for _, collection := range []string{"groupMembers", "bindingActivations", "packageAssignments", "packageRequests"} {
		if err := remove(collection, byIdentity()); err != nil {
			return nil, err
		}
	}
	// A tombstone is nobody's manager.
	reports, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "managerId", identityID), nil)
	if err != nil {
		return nil, err
	}
	for _, report := range reports {
		rest := report.Spread()
		rest.Delete("managerId")
		if _, err := tx.Put(ctx, "identities", rest); err != nil {
			return nil, err
		}
	}
	for _, collection := range []string{"principalBoundaries", "authPasskeys", "passwordHistory", "externalIdentities"} {
		if err := remove(collection, byIdentity()); err != nil {
			return nil, err
		}
	}
	// Onboarding progress carries the person's form answers.
	if err := remove("onboardingProgress", core.NewObject("tenantId", tenantID, "subjectId", identityID)); err != nil {
		return nil, err
	}
	// Threat detection (threats.ts): the sign-in baseline (networks, user agents) and the risk record go with the
	// person; detections and incidents stay as the investigation record.
	for _, collection := range []string{"threatBaselines", "identityRisk"} {
		if err := remove(collection, byIdentity()); err != nil {
			return nil, err
		}
	}
	// Device posture (devices.ts): self-enrolled devices retire with their keys, managed ones lose their owner.
	if err := ReleaseDevicesOf(ctx, tx, identity, server.Now()); err != nil {
		return nil, err
	}
	// Teams and departments (teams.ts, departments.ts): memberships end, departments they head lose their head.
	if _, err := RemoveFromAllTeams(ctx, tx, jsString(tenantID), identityID, server.Now()); err != nil {
		return nil, err
	}
	if _, err := ReleaseDepartments(ctx, tx, jsString(tenantID), identityID, server.Now(), ""); err != nil {
		return nil, err
	}
	if err := remove("relationships", core.NewObject("tenantId", tenantID, "subjectType", "identity", "subjectId", identityID)); err != nil {
		return nil, err
	}
	// Delegations the person gave AI agents (or an agent held) end with the identity (delegations.ts).
	if _, err := RevokeDelegationsOf(ctx, server, tx, identity, jsString(principal.Identity.Get("id"))); err != nil {
		return nil, err
	}
	// Current consent decisions and restrictions go; their history stays as proof (privacy.ts).
	if err := ReleasePrivacyRecords(ctx, tx, identity); err != nil {
		return nil, err
	}
	// App assignments and launch history go; apps they owned lose them as an owner (applications.ts).
	if err := ReleaseAppRecordsOf(ctx, tx, identity); err != nil {
		return nil, err
	}
	// Direct license assignments go and seats are released; waiting people move up (licenses.ts).
	if _, err := ReleaseLicensesOf(ctx, server, tx, identity, principal); err != nil {
		return nil, err
	}
	// A deleted guest's account row goes; guests the person sponsored are flagged for a new sponsor (guests.ts).
	if err := ReleaseGuestRecords(ctx, server, tx, principal, identity); err != nil {
		return nil, err
	}
	// A clearance ends as terminated history, its read-ins released (clearances.ts; only with the `clearances` option).
	if server.Options.Clearances != nil {
		if err := ReleaseClearancesOf(ctx, tx, identity, server.Now(), jsString(principal.Identity.Get("id"))); err != nil {
			return nil, err
		}
	}
	mfa, err := tx.Get(ctx, "authMfa", identityID)
	if err != nil {
		return nil, err
	}
	if mfa != nil {
		if err := tx.Delete(ctx, "authMfa", identityID); err != nil {
			return nil, err
		}
	}
	authorities, err := tx.Find(ctx, "grantAuthorities", byIdentity(), nil)
	if err != nil {
		return nil, err
	}
	for _, authority := range authorities {
		if !truthy(authority.Get("revoked")) {
			if _, err := tx.Put(ctx, "grantAuthorities", authority.Spread(core.NewObject("revoked", true))); err != nil {
				return nil, err
			}
		}
	}
	links, err := identityLinksOf(ctx, tx, identityID)
	if err != nil {
		return nil, err
	}
	for _, link := range links {
		if !truthy(link.Get("revoked")) {
			if _, err := tx.Put(ctx, "identityLinks", link.Spread(core.NewObject("revoked", true))); err != nil {
				return nil, err
			}
		}
	}
	requests, err := tx.Find(ctx, "accessRequests", core.NewObject("tenantId", tenantID, "requesterId", identityID, "status", "pending"), nil)
	if err != nil {
		return nil, err
	}
	for _, request := range requests {
		if _, err := tx.Put(ctx, "accessRequests", request.Spread(core.NewObject("status", "cancelled", "reviewedAt", float64(server.Now())))); err != nil {
			return nil, err
		}
	}
	deletedEmail := identity.Get("email")
	tombstone := identity.Spread()
	for _, key := range []string{"passwordHash", "email", "phone", "managerId"} {
		tombstone.Delete(key)
	}
	tombstone.Assign(core.NewObject(
		"uniqueKey", "deleted:"+identityID,
		"status", "deleted",
		"owner", false,
		"rootAdmin", false,
		"emailVerified", false,
		"deletedAt", float64(server.Now()),
	))
	if !isUndefined(deletedEmail) {
		tombstone.Set("deletedEmail", deletedEmail)
	}
	stored, err := tx.Put(ctx, "identities", tombstone)
	if err != nil {
		return nil, err
	}
	return PublicIdentity(stored), nil
}

// assertAccountControl: whoever controls an account's sign-in address or triggers its password reset controls the
// account, so iam:identities:update alone must not reach an owner or a root administrator (that would be a takeover,
// and it would bypass the ban on impersonating them). An owner's needs another owner of the same tenant or a root
// principal; a root administrator's needs a root principal. The refusal is audited as a denial.
func assertAccountControl(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, identity *core.Object) error {
	rootAdmin := truthy(identity.Get("rootAdmin"))
	if !truthy(identity.Get("owner")) && !rootAdmin {
		return nil
	}
	root, err := server.RootPrincipal(ctx, tx, principal)
	if err != nil {
		return err
	}
	if root {
		return nil
	}
	if !rootAdmin && truthy(principal.Identity.Get("owner")) && core.StrictEquals(principal.Identity.Get("tenantId"), identity.Get("tenantId")) {
		return nil
	}
	if rootAdmin {
		return NewOperationDenied("Only a root administrator can change a root administrator’s sign-in address or password")
	}
	return NewOperationDenied("Only an owner can change an owner’s sign-in address or password")
}

// ownsTenant: the caller is an owner of this tenant in person: the tenant's own owner account on an ordinary
// session. An assumed role never counts, even when its source account owns another tenant, because a role session
// carries only the role's grants.
func ownsTenant(principal *Principal, tenantID any) bool {
	return principal.Session.Get("kind") == "user" &&
		truthy(principal.Identity.Get("owner")) &&
		core.StrictEquals(principal.Identity.Get("tenantId"), tenantID) &&
		core.StrictEquals(principal.Session.Get("tenantId"), tenantID)
}

// identityOwnerOrRoot is `ownsTenant(principal, tenantId) || (await ctx.rootPrincipal(tx, principal))`.
func identityOwnerOrRoot(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID any) (bool, error) {
	if ownsTenant(principal, tenantID) {
		return true, nil
	}
	return server.RootPrincipal(ctx, tx, principal)
}

// AssertOwnerControl (api/identities.ts assertOwnerControl): Deleting, disabling, or scheduling the deactivation of
// an owner removes an owner as surely as `setOwner(false)` or `offboard` does, so it needs the same caller: an owner
// of the tenant in person or a root principal, never iam:identities:update or iam:identities:delete alone. The
// refusal is audited as a denial.
func AssertOwnerControl(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, identity *core.Object, message string) (err error) {
	if !truthy(identity.Get("owner")) {
		return nil
	}
	allowed, err := identityOwnerOrRoot(ctx, server, tx, principal, identity.Get("tenantId"))
	if err != nil {
		return err
	}
	if allowed {
		return nil
	}
	return NewOperationDenied(message)
}

// identityDecide is ctx.decisions.decide on an `iam` resource (internal resource) and its `allowed`.
func identityDecide(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID, action, resourceID string) (bool, error) {
	decision, err := server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{
		TenantID: tenantID, Action: action, Resource: ResourceTarget{Type: "iam", ID: resourceID},
	}, true)
	if err != nil {
		return false, err
	}
	return decision.Allowed, nil
}

// assertMaySetProfile: attributes and a manager feed birthright package rules and policy conditions, so choosing
// them when creating an identity is an update: it needs iam:identities:update on the tenant besides
// iam:identities:create.
func assertMaySetProfile(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID string) error {
	allowed, err := identityDecide(ctx, server, tx, principal, tenantID, "iam:identities:update", tenantID)
	if err != nil {
		return err
	}
	if !allowed {
		return NewOperationDenied("Setting attributes or a manager requires iam:identities:update")
	}
	return nil
}

// sameAttributes compares attribute maps by content, whatever order their keys were written in.
func sameAttributes(a, b any) bool {
	canonical := func(value any) string {
		if isUndefined(value) {
			value = core.NewObject()
		}
		object, ok := value.(*core.Object)
		if !ok {
			text, _, _ := core.Stringify(value)
			return text
		}
		keys := object.Keys()
		sort.SliceStable(keys, func(i, j int) bool { return compareUTF16(keys[i], keys[j]) < 0 })
		pairs := make([]any, len(keys))
		for index, key := range keys {
			pairs[index] = []any{key, object.Get(key)}
		}
		text, _, _ := core.Stringify(pairs)
		return text
	}
	return canonical(a) == canonical(b)
}

// RevokeInvitationsBy (api/identities.ts revokeInvitationsBy): The member invitations an identity sent and nobody
// redeemed yet are revoked when it is disabled or leaves (redemption refuses an inactive inviter anyway; this keeps
// `listInvitations` truthful and the tokens dead if it comes back).
func RevokeInvitationsBy(ctx context.Context, tx core.IamStore, identityID string) (err error) {
	invitations, err := tx.Find(ctx, "memberInvitations", core.NewObject("inviterId", identityID), nil)
	if err != nil {
		return err
	}
	for _, invitation := range invitations {
		if !truthy(invitation.Get("consumed")) && !truthy(invitation.Get("revoked")) {
			if _, err := tx.Put(ctx, "memberInvitations", invitation.Spread(core.NewObject("revoked", true))); err != nil {
				return err
			}
		}
	}
	// Guest invitations they sent or sponsor, likewise (guests.ts).
	return RevokeGuestInvitationsBy(ctx, tx, identityID)
}

// managerFor: a manager is another active identity of the tenant, never the person or one of their own reports (no
// cycles).
func managerFor(ctx context.Context, server *ServerContext, tx core.IamStore, identity *core.Object, managerID any) (string, error) {
	candidate, err := Text(managerID, "managerId")
	if err != nil {
		return "", err
	}
	manager, err := server.ActiveIdentity(ctx, tx, candidate, jsString(identity.Get("tenantId")))
	if err != nil {
		return "", err
	}
	if core.StrictEquals(manager.Get("id"), identity.Get("id")) {
		return "", invalidInput("An identity cannot be its own manager")
	}
	if manager.Get("status") != "active" {
		return "", invalidInput("A manager must be an active identity")
	}
	cursor := manager
	for depth := 0; cursor != nil && truthy(cursor.Get("managerId")) && depth < 100; depth++ {
		if core.StrictEquals(cursor.Get("managerId"), identity.Get("id")) {
			return "", invalidInput("That would make the reporting line circular")
		}
		if cursor, err = tx.Get(ctx, "identities", jsString(cursor.Get("managerId"))); err != nil {
			return "", err
		}
	}
	return jsString(manager.Get("id")), nil
}

// identityAfterChange is the `.then((result) => afterIdentityChange(ctx, tenantId, ids, result))` of a mutation.
func identityAfterChange(ctx context.Context, server *ServerContext, tenantID any, ids []string, result any, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	return AfterIdentityChange(ctx, server, jsString(tenantID), ids, result)
}

// identityWithoutTokenHash is `({ tokenHash, uniqueKey, ...safe }) => safe`: a session or invitation without its token hash
// and unique key.
func identityWithoutTokenHash(record *core.Object) *core.Object {
	safe := record.Spread()
	safe.Delete("tokenHash")
	safe.Delete("uniqueKey")
	return safe
}

// identityGrantChecks authorizes the roles and groups `createMany` and `invite` apply: each role (not protected) with
// iam:bindings:create, each group (not a team's) with iam:groups:update and every grant authority of its bindings
// usable by the caller.
func identityGrantChecks(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID string, roleIDs, groupIDs []string) error {
	for _, roleID := range roleIDs {
		role, err := server.Scoped(ctx, tx, "roles", roleID, tenantID)
		if err != nil {
			return err
		}
		if truthy(role.Get("protected")) {
			return core.NewIamError("PROTECTED_RESOURCE", "Use owner transfer for protected roles", 403)
		}
		allowed, err := identityDecide(ctx, server, tx, principal, tenantID, "iam:bindings:create", jsString(role.Get("id")))
		if err != nil {
			return err
		}
		if !allowed {
			return core.NewIamError("ACCESS_DENIED", "Cannot grant this role", 403)
		}
	}
	for _, groupID := range groupIDs {
		group, err := server.Scoped(ctx, tx, "groups", groupID, tenantID)
		if err != nil {
			return err
		}
		if err := AssertNotTeamGroup(group); err != nil {
			return err
		}
		allowed, err := identityDecide(ctx, server, tx, principal, tenantID, "iam:groups:update", groupID)
		if err != nil {
			return err
		}
		if !allowed {
			return core.NewIamError("ACCESS_DENIED", "Cannot add members to this group", 403)
		}
		bindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "group", "subjectId", groupID), nil)
		if err != nil {
			return err
		}
		for _, binding := range bindings {
			if _, err := server.GrantingAuthority(ctx, tx, principal, tenantID, identityAuthorityArg(binding.Get("authorityId"))); err != nil {
				return err
			}
		}
	}
	return nil
}

// identityAuthorityArg is an optional authority ID argument ("" for none).
func identityAuthorityArg(value any) string {
	if s, ok := value.(string); ok {
		return s
	}
	return ""
}

// Create is POST {basePath}/identities/create. `expiresAt` schedules deactivation (contractors): credentials stop
// working at that time and the worker disables the identity. A `managerId` also needs iam:identities:update on the
// tenant. `emailVerified` records an address another system already verified (a migration); `providers` links
// external sign-ins ahead of the first one, so that sign-in finds this account instead of failing with
// `ACCOUNT_LINK_REQUIRED`.
func (api *IdentitiesAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesCreateInput]) (Out[apitypes.IdentitiesCreateOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	created, err := Operate(ctx, server.Operations, credential, tenantID, "iam:identities:create", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		var expiresAt any = core.Undefined
		if !isUndefined(input.Get("expiresAt")) {
			expiry, err := server.BindingExpiry(input.Get("expiresAt"))
			if err != nil {
				return nil, err
			}
			expiresAt = expiry
		}
		if !isUndefined(input.Get("managerId")) {
			if err := assertMaySetProfile(ctx, server, tx, principal, jsString(tenantID)); err != nil {
				return nil, err
			}
		}
		emailVerified, err := identityFlag(input.Get("emailVerified"), "emailVerified")
		if err != nil {
			return nil, err
		}
		providers, err := identityProviderLinks(input.Get("providers"))
		if err != nil {
			return nil, err
		}
		address, err := Email(input.Get("email"))
		if err != nil {
			return nil, err
		}
		name, err := Text(input.Get("name"), "name")
		if err != nil {
			return nil, err
		}
		password := input.Get("password")
		identity, err := server.Auth.CreateIdentity(ctx, tx, auth.CreateIdentityInput{
			TenantID: tenantID, Email: address, Name: name, Password: password, HasPassword: !isUndefined(password),
			EmailVerified: emailVerified,
		})
		if err != nil {
			return nil, err
		}
		for _, link := range providers {
			if _, err := insertIdentityProviderLink(ctx, tx, jsString(tenantID), jsString(identity.Get("id")), link, server.Now()); err != nil {
				return nil, err
			}
		}
		var managerID any = core.Undefined
		if !isUndefined(input.Get("managerId")) {
			manager, err := managerFor(ctx, server, tx, identity, input.Get("managerId"))
			if err != nil {
				return nil, err
			}
			managerID = manager
		}
		if isUndefined(expiresAt) && isUndefined(managerID) {
			return PublicIdentity(identity), nil
		}
		next := identity.Spread()
		if !isUndefined(expiresAt) {
			next.Set("expiresAt", expiresAt)
		}
		if !isUndefined(managerID) {
			next.Set("managerId", managerID)
		}
		stored, err := tx.Put(ctx, "identities", next)
		if err != nil {
			return nil, err
		}
		return PublicIdentity(stored), nil
	}, false)
	var ids []string
	if created != nil {
		ids = []string{jsString(created.Get("id"))}
	}
	result, err := identityAfterChange(ctx, server, tenantID, ids, created, err)
	return Out[apitypes.IdentitiesCreateOutput]{Value: result}, err
}

// createManyItem is one validated person of createMany.
type createManyItem struct {
	email         string
	name          string
	password      any
	attributes    *core.Object
	roleIDs       []string
	groupIDs      []string
	expiresAt     any
	emailVerified bool
	providers     []providerLink
}

// CreateMany is POST {basePath}/identities/createMany. Creates up to 100 identities atomically with optional
// attributes, roles, and groups (bulk onboarding). Roles and groups are authorized once like invitations:
// `iam:bindings:create` on each role under the caller's grant authority and `iam:groups:update` on each group (plus
// iam:licenses:assign when a license product is assigned to one of them); attributes need iam:identities:update on
// the tenant. One failure rejects the whole batch. Per person, `emailVerified` and `providers` work as in `create`
// (migrations from another identity provider).
func (api *IdentitiesAPI) CreateMany(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesCreateManyInput]) (Out[apitypes.IdentitiesCreateManyOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	outcome, err := Operate(ctx, server.Operations, credential, tenantID, "iam:identities:create", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, realm := call.Tx, call.Principal, call.Tenant
		list, ok := input.Get("identities").([]any)
		if !ok || len(list) == 0 || len(list) > 100 {
			return nil, invalidInput("Provide 1-100 identities")
		}
		if realm.Get("status") != "active" {
			return nil, core.NewIamError("TENANT_INACTIVE", "Tenant must be active")
		}
		realmID := jsString(realm.Get("id"))
		items := make([]createManyItem, 0, len(list))
		for _, entry := range list {
			value, err := Object(entry)
			if err != nil {
				return nil, err
			}
			var item createManyItem
			if item.email, err = Email(value.Get("email")); err != nil {
				return nil, err
			}
			if item.name, err = Text(value.Get("name"), "name"); err != nil {
				return nil, err
			}
			item.password = value.Get("password")
			if item.attributes, err = AttributeValues(server.Catalog.IdentityAttributes, value.Get("attributes")); err != nil {
				return nil, err
			}
			roleIDs, err := Strings(coalesce(value.Get("roleIds"), []any{}), "roleIds")
			if err != nil {
				return nil, err
			}
			item.roleIDs = unique(roleIDs)
			groupIDs, err := Strings(coalesce(value.Get("groupIds"), []any{}), "groupIds")
			if err != nil {
				return nil, err
			}
			item.groupIDs = unique(groupIDs)
			item.expiresAt = core.Undefined
			if !isUndefined(value.Get("expiresAt")) {
				expiry, err := server.BindingExpiry(value.Get("expiresAt"))
				if err != nil {
					return nil, err
				}
				item.expiresAt = expiry
			}
			if item.emailVerified, err = identityFlag(value.Get("emailVerified"), "emailVerified"); err != nil {
				return nil, err
			}
			if item.providers, err = identityProviderLinks(value.Get("providers")); err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		for _, item := range items {
			if item.attributes.Len() > 0 {
				if err := assertMaySetProfile(ctx, server, tx, principal, realmID); err != nil {
					return nil, err
				}
				break
			}
		}
		roleIDs, groupIDs := newOrderedSet(), newOrderedSet()
		for _, item := range items {
			for _, roleID := range item.roleIDs {
				roleIDs.Add(roleID)
			}
			for _, groupID := range item.groupIDs {
				groupIDs.Add(groupID)
			}
		}
		var authority *core.Object
		if roleIDs.Len() > 0 {
			granting, err := server.GrantingAuthority(ctx, tx, principal, realmID, "")
			if err != nil {
				return nil, err
			}
			authority = granting
		}
		if err := identityGrantChecks(ctx, server, tx, principal, realmID, roleIDs.Values(), groupIDs.Values()); err != nil {
			return nil, err
		}
		// New members of a licensed group claim its seats: that needs iam:licenses:assign (groups.ts).
		if err := AssertMayClaimLicenses(ctx, server, tx, principal, realmID, stringsOf(groupIDs.Values()), identitySeatsMessage); err != nil {
			return nil, err
		}
		created := []any{}
		for _, item := range items {
			identity, err := server.Auth.CreateIdentity(ctx, tx, auth.CreateIdentityInput{
				TenantID: realmID, Email: item.email, Name: item.name, Password: item.password,
				HasPassword: !isUndefined(item.password), EmailVerified: item.emailVerified,
			})
			if err != nil {
				return nil, err
			}
			identityID := jsString(identity.Get("id"))
			for _, link := range item.providers {
				if _, err := insertIdentityProviderLink(ctx, tx, realmID, identityID, link, server.Now()); err != nil {
					return nil, err
				}
			}
			if item.attributes.Len() > 0 || !isUndefined(item.expiresAt) {
				next := identity.Spread()
				if item.attributes.Len() > 0 {
					next.Set("attributes", item.attributes)
				}
				if !isUndefined(item.expiresAt) {
					next.Set("expiresAt", item.expiresAt)
				}
				if identity, err = tx.Put(ctx, "identities", next); err != nil {
					return nil, err
				}
			}
			for _, roleID := range item.roleIDs {
				authorityID := jsString(authority.Get("id"))
				if _, err := tx.Insert(ctx, "bindings", core.NewObject(
					"id", ID(),
					"tenantId", realmID,
					"uniqueKey", "identity:"+identityID+":"+roleID+":"+authorityID,
					"subjectType", "identity",
					"subjectId", identityID,
					"roleId", roleID,
					"authorityId", authorityID,
				)); err != nil {
					return nil, err
				}
			}
			for _, groupID := range item.groupIDs {
				if _, err := tx.Insert(ctx, "groupMembers", core.NewObject(
					"id", ID(),
					"tenantId", realmID,
					"uniqueKey", groupID+":"+identityID,
					"groupId", groupID,
					"identityId", identityID,
				)); err != nil {
					return nil, err
				}
			}
			created = append(created, PublicIdentity(identity))
		}
		return core.NewObject("identities", created), nil
	}, false)
	var ids []string
	if outcome != nil {
		list, _ := outcome.Get("identities").([]any)
		for _, identity := range list {
			ids = append(ids, jsString(member(identity, "id")))
		}
	}
	result, err := identityAfterChange(ctx, server, tenantID, ids, outcome, err)
	return Out[apitypes.IdentitiesCreateManyOutput]{Value: result}, err
}

// identitySlice is `limit === undefined ? list.slice(offset) : list.slice(offset, offset + limit)` (limit < 0: none).
func identitySlice(list []any, offset int, limit int) []any {
	if offset > len(list) {
		offset = len(list)
	}
	end := len(list)
	if limit >= 0 && offset+limit < end {
		end = offset + limit
	}
	return append([]any{}, list[offset:end]...)
}

// List is POST {basePath}/identities/list. Deleted identities are omitted unless includeDeleted is set; kind and
// status narrow the list. `query` matches the name or email case-insensitively; `expiresBefore` keeps identities
// scheduled to deactivate before that time (expiry reports); `limit`/`offset` page through the result, ordered by
// name then ID.
func (api *IdentitiesAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesListInput]) (Out[apitypes.IdentitiesListOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:identities:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		filter := core.NewObject("tenantId", tenantID)
		if kind := input.Get("kind"); !isUndefined(kind) {
			if kind != "user" && kind != "service" && kind != "agent" {
				return nil, invalidInput("Invalid identity kind")
			}
			filter.Set("kind", kind)
		}
		status := input.Get("status")
		if !isUndefined(status) {
			if status != "active" && status != "disabled" && status != "deleted" {
				return nil, invalidInput("Invalid identity status")
			}
			filter.Set("status", status)
		}
		query, hasQuery := "", false
		if !isUndefined(input.Get("query")) {
			text, err := Text(input.Get("query"), "query", 256)
			if err != nil {
				return nil, err
			}
			query, hasQuery = core.JSLower(text), true
		}
		expiresBefore, hasExpiresBefore := 0.0, false
		if !isUndefined(input.Get("expiresBefore")) {
			value, err := Integer(input.Get("expiresBefore"), "expiresBefore", 0, maxSafeInteger)
			if err != nil {
				return nil, err
			}
			expiresBefore, hasExpiresBefore = value, true
		}
		limit := -1
		if !isUndefined(input.Get("limit")) {
			value, err := Integer(input.Get("limit"), "limit", 1, 1000)
			if err != nil {
				return nil, err
			}
			limit = int(value)
		}
		offset, err := Integer(coalesce(input.Get("offset"), 0.0), "offset", 0, 1_000_000)
		if err != nil {
			return nil, err
		}
		identities, err := call.Tx.Find(ctx, "identities", filter, nil)
		if err != nil {
			return nil, err
		}
		includeDeleted := input.Get("includeDeleted") == true || status == "deleted"
		matches := []*core.Object{}
		for _, identity := range identities {
			if !includeDeleted && identity.Get("status") == "deleted" {
				continue
			}
			if hasQuery {
				name, _ := identity.Get("name").(string)
				email, hasEmail := identity.Get("email").(string)
				if !strings.Contains(core.JSLower(name), query) && !(hasEmail && strings.Contains(core.JSLower(email), query)) {
					continue
				}
			}
			if hasExpiresBefore {
				expiresAt, ok := identity.Get("expiresAt").(float64)
				if !ok || expiresAt > expiresBefore {
					continue
				}
			}
			matches = append(matches, identity)
		}
		identitySortByName(matches)
		list := make([]any, len(matches))
		for index, identity := range matches {
			list[index] = PublicIdentity(identity)
		}
		return identitySlice(list, int(offset), limit), nil
	}, false)
	return Out[apitypes.IdentitiesListOutput]{Value: result}, err
}

// identitySortByName is `a.name.localeCompare(b.name, 'en') || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)`.
func identitySortByName(list []*core.Object) {
	sort.SliceStable(list, func(i, j int) bool {
		left, _ := list[i].Get("name").(string)
		right, _ := list[j].Get("name").(string)
		if order := localeCompare(left, right); order != 0 {
			return order < 0
		}
		return ByID(list[i], list[j]) < 0
	})
}

// identityNewestFirst orders records by a numeric member descending, then id ascending.
func identityNewestFirst(list []*core.Object, key string) {
	sort.SliceStable(list, func(i, j int) bool {
		left, _ := list[i].Get(key).(float64)
		right, _ := list[j].Get(key).(float64)
		if difference := right - left; difference != 0 && difference == difference {
			return difference < 0
		}
		return ByID(list[i], list[j]) < 0
	})
}

// ListSessions is POST {basePath}/identities/listSessions: sessions of one identity for administrators (device
// lists, support); token hashes are never returned.
func (api *IdentitiesAPI) ListSessions(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesListSessionsInput]) (Out[apitypes.IdentitiesListSessionsOutput], error) {
	server := api.server
	tenantID, identityID := input.Get("tenantId"), input.Get("identityId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:identities:read", jsString(identityID), func(ctx context.Context, call MutationContext) ([]any, error) {
		if _, err := server.Scoped(ctx, call.Tx, "identities", identityID, jsString(tenantID)); err != nil {
			return nil, err
		}
		sessions, err := call.Tx.Find(ctx, "sessions", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
		if err != nil {
			return nil, err
		}
		now := float64(server.Now())
		live := []*core.Object{}
		for _, session := range sessions {
			if expiresAt, _ := session.Get("expiresAt").(float64); expiresAt > now {
				live = append(live, session)
			}
		}
		identityNewestFirst(live, "lastSeenAt")
		list := make([]any, len(live))
		for index, session := range live {
			list[index] = identityWithoutTokenHash(session)
		}
		return list, nil
	}, false)
	return Out[apitypes.IdentitiesListSessionsOutput]{Value: result}, err
}

// Get is POST {basePath}/identities/get. Returns one identity by ID, including the tombstone of a deleted identity.
func (api *IdentitiesAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesGetInput]) (Out[apitypes.IdentitiesGetOutput], error) {
	server := api.server
	tenantID, identityID := input.Get("tenantId"), input.Get("identityId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:identities:read", jsString(identityID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		identity, err := server.Scoped(ctx, call.Tx, "identities", identityID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		return PublicIdentity(identity), nil
	}, false)
	return Out[apitypes.IdentitiesGetOutput]{Value: result}, err
}

// identityRecordList is a record list as a model array.
func identityRecordList(records []*core.Object) []any {
	list := make([]any, len(records))
	for index, record := range records {
		list[index] = record
	}
	return list
}

// Export is POST {basePath}/identities/export. Data-subject export: everything this tenant stores about one
// identity, as JSON. Requires recent authentication and iam:identities:read on the identity. Audit events the
// identity performed are included only when the caller also holds iam:audit:read (newest first, at most 5000).
// Secrets, hashes, and tokens are never included.
func (api *IdentitiesAPI) Export(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesExportInput]) (Out[apitypes.IdentitiesExportOutput], error) {
	server := api.server
	rawTenantID, identityID := input.Get("tenantId"), input.Get("identityId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:identities:read", jsString(identityID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		tenantID := jsString(rawTenantID)
		identity, err := server.Scoped(ctx, tx, "identities", identityID, tenantID)
		if err != nil {
			return nil, err
		}
		id := identity.Get("id")
		find := func(collection string, filter *core.Object) ([]*core.Object, error) {
			return tx.Find(ctx, collection, filter, nil)
		}
		groups := []any{}
		memberships, err := find("groupMembers", core.NewObject("tenantId", tenantID, "identityId", id))
		if err != nil {
			return nil, err
		}
		for _, membership := range memberships {
			group, err := tx.Get(ctx, "groups", jsString(membership.Get("groupId")))
			if err != nil {
				return nil, err
			}
			if group != nil && group.Get("tenantId") == tenantID {
				groups = append(groups, group)
			}
		}
		linkRows, err := identityLinksOf(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		links := make([]any, len(linkRows))
		for index, link := range linkRows {
			linked := link.Get("leftId")
			if core.StrictEquals(link.Get("leftId"), id) {
				linked = link.Get("rightId")
			}
			links[index] = core.NewObject("id", link.Get("id"), "linkedIdentityId", linked, "revoked", link.Get("revoked"))
		}
		auditAllowed, err := identityDecide(ctx, server, tx, principal, tenantID, "iam:audit:read", tenantID)
		if err != nil {
			return nil, err
		}
		var audit any = core.Undefined
		if auditAllowed {
			events, err := find("audit", core.NewObject("tenantId", tenantID, "actorId", id))
			if err != nil {
				return nil, err
			}
			identityNewestFirst(events, "timestamp")
			if len(events) > 5000 {
				events = events[:5000]
			}
			audit = identityRecordList(events)
		}
		if err := server.Events.Audit(ctx, tx, principal, "identity:export", tenantID, jsString(id), "allow", false,
			core.NewObject("kind", identity.Get("kind"), "auditIncluded", auditAllowed)); err != nil {
			return nil, err
		}
		sessionRows, err := find("sessions", core.NewObject("tenantId", tenantID, "identityId", id))
		if err != nil {
			return nil, err
		}
		sessions := make([]any, len(sessionRows))
		for index, session := range sessionRows {
			sessions[index] = identityWithoutTokenHash(session)
		}
		mfa, err := tx.Get(ctx, "authMfa", jsString(id))
		if err != nil {
			return nil, err
		}
		passkeyRows, err := find("authPasskeys", core.NewObject("tenantId", tenantID, "identityId", id))
		if err != nil {
			return nil, err
		}
		passkeys := make([]any, len(passkeyRows))
		for index, key := range passkeyRows {
			passkeys[index] = core.NewObject("id", key.Get("id"), "credentialId", key.Get("credentialId"), "transports", key.Get("transports"))
		}
		mappingRows, err := find("externalIdentities", core.NewObject("tenantId", tenantID, "identityId", id))
		if err != nil {
			return nil, err
		}
		externalIdentities := make([]any, len(mappingRows))
		for index, mapping := range mappingRows {
			externalIdentities[index] = core.NewObject("providerId", mapping.Get("providerId"), "issuer", mapping.Get("issuer"), "subject", mapping.Get("subject"))
		}
		effective, err := server.Decisions.EffectiveBindings(ctx, tx, tenantID, jsString(id))
		if err != nil {
			return nil, err
		}
		bindings := make([]any, len(effective))
		for index, binding := range effective {
			bindings[index] = binding.Model()
		}
		relationships, err := find("relationships", core.NewObject("tenantId", tenantID, "subjectType", "identity", "subjectId", id))
		if err != nil {
			return nil, err
		}
		accessRequests, err := find("accessRequests", core.NewObject("tenantId", tenantID, "requesterId", id))
		if err != nil {
			return nil, err
		}
		boundaryRows, err := find("principalBoundaries", core.NewObject("tenantId", tenantID, "identityId", id))
		if err != nil {
			return nil, err
		}
		boundaries := make([]any, len(boundaryRows))
		for index, boundary := range boundaryRows {
			boundaries[index] = boundary.Get("document")
		}
		authorityRows, err := find("grantAuthorities", core.NewObject("tenantId", tenantID, "identityId", id))
		if err != nil {
			return nil, err
		}
		authorities := make([]any, len(authorityRows))
		for index, authority := range authorityRows {
			authorities[index] = core.NewObject("id", authority.Get("id"), "revoked", authority.Get("revoked"), "parentAuthorityId", authority.Get("parentAuthorityId"))
		}
		scimRows, err := find("scimUsers", core.NewObject("tenantId", tenantID, "identityId", id))
		if err != nil {
			return nil, err
		}
		scim := make([]any, len(scimRows))
		for index, row := range scimRows {
			scim[index] = core.NewObject("connectionId", row.Get("connectionId"), "externalId", row.Get("externalId"), "userName", row.Get("userName"), "active", row.Get("active"))
		}
		return core.NewObject(
			"exportedAt", float64(server.Now()),
			"tenantId", tenantID,
			"identity", PublicIdentity(identity),
			"sessions", sessions,
			"mfa", core.NewObject("enabled", mfa != nil && truthy(mfa.Get("enabled"))),
			"passkeys", passkeys,
			"externalIdentities", externalIdentities,
			"bindings", bindings,
			"groups", groups,
			"relationships", identityRecordList(relationships),
			"accessRequests", identityRecordList(accessRequests),
			"boundaries", boundaries,
			"grantAuthorities", authorities,
			"links", links,
			"scim", scim,
			"auditIncluded", auditAllowed,
			"audit", audit,
		), nil
	}, false)
	return Out[apitypes.IdentitiesExportOutput]{Value: result}, err
}

// Unlock is POST {basePath}/identities/unlock. Unlocks an account: clears the sign-in, recovery, and MFA rate-limit
// counters for the identity's email, phone, and ID. Requires recent authentication and iam:identities:update; custom
// limiters without `reset` report `supported: false`.
func (api *IdentitiesAPI) Unlock(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesUnlockInput]) (Out[apitypes.IdentitiesUnlockOutput], error) {
	server := api.server
	tenantID, identityID := input.Get("tenantId"), input.Get("identityId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:identities:update", jsString(identityID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		identity, err := server.ActiveIdentity(ctx, tx, identityID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		reset, err := server.Auth.ResetRateLimits(ctx, identity)
		if err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "identity:unlock", jsString(tenantID), jsString(identity.Get("id")), "allow", false,
			core.NewObject("supported", reset.Get("supported"), "cleared", reset.Get("cleared"))); err != nil {
			return nil, err
		}
		return reset, nil
	}, false)
	return Out[apitypes.IdentitiesUnlockOutput]{Value: result}, err
}

// Impersonate is POST {basePath}/identities/impersonate. Opens a session as a member ("view as") for support and
// troubleshooting. Requires recent authentication, iam:identities:impersonate on the member, and the tenant's
// `allowImpersonation` policy. The member must be an active person who is neither the caller, an owner, nor a root
// administrator. The session lasts at most `durationMs` (one minute to eight hours, one hour by default), never
// outlives the caller's own session, cannot perform operations that need recent authentication, assume roles, or
// grant OAuth consent, and every audit record it produces carries `impersonatorId`. Audited as
// `identity:impersonate` with the reason; the token is returned in the body only, never as a cookie.
func (api *IdentitiesAPI) Impersonate(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesImpersonateInput]) (Out[apitypes.IdentitiesImpersonateOutput], error) {
	server := api.server
	tenantID, identityID := input.Get("tenantId"), input.Get("identityId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:identities:impersonate", jsString(identityID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		reason, err := Text(input.Get("reason"), "reason", 512)
		if err != nil {
			return nil, err
		}
		durationMs, err := Integer(coalesce(input.Get("durationMs"), 3_600_000.0), "durationMs", 60_000, 8*3_600_000)
		if err != nil {
			return nil, err
		}
		identity, err := server.ActiveIdentity(ctx, tx, identityID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		if core.StrictEquals(identity.Get("id"), principal.Identity.Get("id")) {
			return nil, invalidInput("You cannot impersonate yourself")
		}
		if identity.Get("kind") != "user" {
			return nil, invalidInput("Only people can be impersonated")
		}
		if truthy(identity.Get("rootAdmin")) || truthy(identity.Get("owner")) {
			return nil, core.NewIamError("ACCESS_DENIED", "Owners and root administrators cannot be impersonated", 403)
		}
		issued, err := server.Auth.IssueImpersonationSession(ctx, tx, principal.Auth(), identity, durationMs)
		if err != nil {
			return nil, err
		}
		session, _ := issued.Get("session").(*core.Object)
		if session == nil {
			session = core.NewObject()
		}
		if err := server.Events.Audit(ctx, tx, principal, "identity:impersonate", jsString(tenantID), jsString(identity.Get("id")), "allow", false,
			core.NewObject("reason", reason, "sessionId", session.Get("id"), "expiresAt", session.Get("expiresAt"))); err != nil {
			return nil, err
		}
		return core.NewObject("token", issued.Get("token"), "session", identityWithoutTokenHash(session), "identity", PublicIdentity(identity)), nil
	}, false)
	return Out[apitypes.IdentitiesImpersonateOutput]{Value: result}, err
}

// RequestPasswordReset is POST {basePath}/identities/requestPasswordReset. Queues a password-reset email for a
// member on an administrator's behalf (support, onboarding without a password). Requires recent authentication and
// iam:identities:update; audited as `identity:password-reset`.
func (api *IdentitiesAPI) RequestPasswordReset(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesRequestPasswordResetInput]) (Out[apitypes.IdentitiesRequestPasswordResetOutput], error) {
	server := api.server
	tenantID, identityID := input.Get("tenantId"), input.Get("identityId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:identities:update", jsString(identityID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		identity, err := server.ActiveIdentity(ctx, tx, identityID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		if err := assertAccountControl(ctx, server, tx, principal, identity); err != nil {
			return nil, err
		}
		if err := server.Auth.IssuePasswordReset(ctx, tx, identity); err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "identity:password-reset", jsString(tenantID), jsString(identity.Get("id")), "allow", false, nil); err != nil {
			return nil, err
		}
		return core.NewObject("queued", true, "email", identity.Get("email")), nil
	}, false)
	return Out[apitypes.IdentitiesRequestPasswordResetOutput]{Value: result}, err
}

// LinkProvider is POST {basePath}/identities/linkProvider. Links an external sign-in (OAuth/OIDC or SAML) to an
// existing account, so that IdP account signs in to it with no account-linking step: migrations, or a person whose
// IdP subject is known before their first sign-in. Whoever links an external account controls the account, so this
// needs what changing its sign-in address needs: recent authentication, iam:identities:update, and for an owner
// another owner or a root principal (a root administrator only by a root principal). Audited as
// `identity:link-provider`.
func (api *IdentitiesAPI) LinkProvider(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesLinkProviderInput]) (Out[apitypes.IdentitiesLinkProviderOutput], error) {
	server := api.server
	tenantID, identityID := input.Get("tenantId"), input.Get("identityId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:identities:update", jsString(identityID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		var body any = core.Undefined
		if input.Body != nil {
			body = input.Body
		}
		link, err := identityProviderLinkInput(body)
		if err != nil {
			return nil, err
		}
		identity, err := server.ActiveIdentity(ctx, tx, identityID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		if identity.Get("kind") != "user" {
			return nil, invalidInput("Only people sign in through external providers")
		}
		if err := assertAccountControl(ctx, server, tx, principal, identity); err != nil {
			return nil, err
		}
		created, err := insertIdentityProviderLink(ctx, tx, jsString(tenantID), jsString(identity.Get("id")), link, server.Now())
		if err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "identity:link-provider", jsString(tenantID), jsString(identity.Get("id")), "allow", false,
			core.NewObject("providerId", link.ProviderID, "linkId", created.Get("id"))); err != nil {
			return nil, err
		}
		return created, nil
	}, false)
	return Out[apitypes.IdentitiesLinkProviderOutput]{Value: result}, err
}

// UnlinkProvider is POST {basePath}/identities/unlinkProvider. Removes a linked external sign-in (`listProviders`
// gives the IDs); that IdP account no longer signs in to this account. Requires recent authentication and
// iam:identities:update; audited as `identity:unlink-provider`.
func (api *IdentitiesAPI) UnlinkProvider(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesUnlinkProviderInput]) (Out[apitypes.IdentitiesUnlinkProviderOutput], error) {
	server := api.server
	tenantID, identityID := input.Get("tenantId"), input.Get("identityId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:identities:update", jsString(identityID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		identity, err := server.Scoped(ctx, tx, "identities", identityID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		if err := assertAccountControl(ctx, server, tx, principal, identity); err != nil {
			return nil, err
		}
		linkID, err := Text(input.Get("linkId"), "linkId")
		if err != nil {
			return nil, err
		}
		link, err := tx.Get(ctx, "externalIdentities", linkID)
		if err != nil {
			return nil, err
		}
		if link == nil || !core.StrictEquals(link.Get("tenantId"), tenantID) || !core.StrictEquals(link.Get("identityId"), identity.Get("id")) {
			return nil, core.NewIamError("NOT_FOUND", "Linked sign-in not found", 404)
		}
		if err := tx.Delete(ctx, "externalIdentities", jsString(link.Get("id"))); err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "identity:unlink-provider", jsString(tenantID), jsString(identity.Get("id")), "allow", false,
			core.NewObject("providerId", jsString(link.Get("providerId")), "linkId", link.Get("id"))); err != nil {
			return nil, err
		}
		return identityProviderLinkView(link), nil
	}, false)
	return Out[apitypes.IdentitiesUnlinkProviderOutput]{Value: result}, err
}

// ListProviders is POST {basePath}/identities/listProviders: the external sign-ins linked to an account
// (iam:identities:read), sorted by provider.
func (api *IdentitiesAPI) ListProviders(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesListProvidersInput]) (Out[apitypes.IdentitiesListProvidersOutput], error) {
	server := api.server
	tenantID, identityID := input.Get("tenantId"), input.Get("identityId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:identities:read", jsString(identityID), func(ctx context.Context, call MutationContext) ([]any, error) {
		identity, err := server.Scoped(ctx, call.Tx, "identities", identityID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		rows, err := call.Tx.Find(ctx, "externalIdentities", core.NewObject("tenantId", tenantID, "identityId", identity.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		views := make([]*core.Object, len(rows))
		for index, row := range rows {
			views[index] = identityProviderLinkView(row)
		}
		sort.SliceStable(views, func(i, j int) bool {
			return compareUTF16(jsString(views[i].Get("providerId")), jsString(views[j].Get("providerId"))) < 0
		})
		return identityRecordList(views), nil
	}, false)
	return Out[apitypes.IdentitiesListProvidersOutput]{Value: result}, err
}

// RevokeSessions is POST {basePath}/identities/revokeSessions. Ends every session of an identity without disabling
// it (incident response, lost device). Requires recent authentication. By default API keys are deleted too; with
// `keepApiKeys: true` every other credential (user, role and session-token sessions, including role sessions it
// assumed elsewhere and session tokens minted from its keys), its remembered devices and pending challenges end while
// the API keys stay valid. Audited as `identity:revoke-sessions` with `{ revoked, keptApiKeys }`.
func (api *IdentitiesAPI) RevokeSessions(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesRevokeSessionsInput]) (Out[apitypes.IdentitiesRevokeSessionsOutput], error) {
	server := api.server
	tenantID, identityID := input.Get("tenantId"), input.Get("identityId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:identities:update", jsString(identityID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		keep := input.Get("keepApiKeys")
		if _, isBool := keep.(bool); !isUndefined(keep) && !isBool {
			return nil, invalidInput("keepApiKeys must be a boolean")
		}
		keepAPIKeys := keep == true
		identity, err := server.Scoped(ctx, tx, "identities", identityID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		if err := identityRootProtected(ctx, server, tx, principal, identity); err != nil {
			return nil, err
		}
		id := jsString(identity.Get("id"))
		revoked := 0
		if !keepAPIKeys {
			sessions, err := tx.Find(ctx, "sessions", core.NewObject("identityId", id), nil)
			if err != nil {
				return nil, err
			}
			revoked = len(sessions)
			if err := server.RevokeAll(ctx, tx, id); err != nil {
				return nil, err
			}
		} else {
			// As revokeAll, minus the API keys: sessions by identity (with the impersonations opened through them),
			// remembered devices, challenges, then role sessions the identity assumed in other tenants.
			sessions, err := tx.Find(ctx, "sessions", core.NewObject("identityId", id), nil)
			if err != nil {
				return nil, err
			}
			for _, session := range sessions {
				if session.Get("kind") == "api-key" {
					continue
				}
				if err := server.Auth.EndSession(ctx, tx, jsString(session.Get("id"))); err != nil {
					return nil, err
				}
				revoked++
			}
			for _, collection := range []string{"authDevices", "authChallenges"} {
				if err := identityRemove(ctx, tx, collection, core.NewObject("identityId", id)); err != nil {
					return nil, err
				}
			}
			assumed, err := tx.Find(ctx, "sessions", core.NewObject("originalIdentityId", id), nil)
			if err != nil {
				return nil, err
			}
			for _, session := range assumed {
				if session.Get("kind") != "api-key" {
					if err := tx.Delete(ctx, "sessions", jsString(session.Get("id"))); err != nil {
						return nil, err
					}
				}
			}
		}
		if err := server.Events.Audit(ctx, tx, principal, "identity:revoke-sessions", jsString(tenantID), id, "allow", false,
			core.NewObject("revoked", float64(revoked), "keptApiKeys", keepAPIKeys)); err != nil {
			return nil, err
		}
		return core.NewObject("revoked", float64(revoked)), nil
	}, false)
	return Out[apitypes.IdentitiesRevokeSessionsOutput]{Value: result}, err
}

// offboardCounts is the counters offboarding reports, in the TypeScript member order.
type offboardCounts struct {
	sessions, bindings, memberships, activations, packages, relationships, accessRequests, authorities int
	resourcesReassigned, resourcesOwned, reportsReassigned                                             int
}

func (c *offboardCounts) model() *core.Object {
	return core.NewObject(
		"sessions", float64(c.sessions),
		"bindings", float64(c.bindings),
		"memberships", float64(c.memberships),
		"activations", float64(c.activations),
		"packages", float64(c.packages),
		"relationships", float64(c.relationships),
		"accessRequests", float64(c.accessRequests),
		"authorities", float64(c.authorities),
		"resourcesReassigned", float64(c.resourcesReassigned),
		"resourcesOwned", float64(c.resourcesOwned),
		"reportsReassigned", float64(c.reportsReassigned),
	)
}

// Offboard is POST {basePath}/identities/offboard. Offboarding in one transaction: disables the identity, ends every
// session and key, removes its role bindings (under the caller's authority, like `bindings.delete`), group
// memberships, activations, relationships, pending access requests and member invitations, revokes the grant
// authorities it holds, and hands the managed resources it owns to `successorId` (or reports them). Ownership is
// removed like `setOwner`, which needs an owner or root caller; the last owner and root administrators are protected.
// The record stays as a disabled identity for retention; `identities.delete` tombstones it later. Requires recent
// authentication and iam:identities:update; audited as `identity:offboard` with the reason and counts.
func (api *IdentitiesAPI) Offboard(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesOffboardInput]) (Out[apitypes.IdentitiesOffboardOutput], error) {
	server := api.server
	rawTenantID, identityID := input.Get("tenantId"), input.Get("identityId")
	outcome, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:identities:update", jsString(identityID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		reason, err := Text(input.Get("reason"), "reason", 512)
		if err != nil {
			return nil, err
		}
		tenantID := jsString(rawTenantID)
		identity, err := server.ActiveIdentity(ctx, tx, identityID, tenantID)
		if err != nil {
			return nil, err
		}
		if core.StrictEquals(identity.Get("id"), principal.Identity.Get("id")) {
			return nil, invalidInput("You cannot offboard yourself")
		}
		if err := identityRootProtected(ctx, server, tx, principal, identity); err != nil {
			return nil, err
		}
		if err := server.ProtectLastOwner(ctx, tx, identity); err != nil {
			return nil, err
		}
		var successor *core.Object
		if !isUndefined(input.Get("successorId")) {
			if successor, err = server.ActiveIdentity(ctx, tx, input.Get("successorId"), tenantID); err != nil {
				return nil, err
			}
		}
		if successor != nil && (core.StrictEquals(successor.Get("id"), identity.Get("id")) || successor.Get("status") != "active") {
			return nil, invalidInput("Successor must be another active identity")
		}
		id := jsString(identity.Get("id"))
		now := func() float64 { return float64(server.Now()) }
		find := func(collection string, filter *core.Object) ([]*core.Object, error) {
			return tx.Find(ctx, collection, filter, nil)
		}
		sessions, err := find("sessions", core.NewObject("identityId", id))
		if err != nil {
			return nil, err
		}
		counts := &offboardCounts{sessions: len(sessions)}
		// Ownership goes first: the protected Owner binding is removed like setOwner(false).
		if truthy(identity.Get("owner")) {
			allowed, err := identityOwnerOrRoot(ctx, server, tx, principal, tenantID)
			if err != nil {
				return nil, err
			}
			if !allowed {
				return nil, core.NewIamError("ACCESS_DENIED", "Only an owner can offboard an owner", 403)
			}
			ownerRoles, err := find("roles", core.NewObject("tenantId", tenantID, "uniqueKey", "system:owner"))
			if err != nil {
				return nil, err
			}
			var ownerRoleID any = ""
			if len(ownerRoles) > 0 {
				ownerRoleID = coalesce(ownerRoles[0].Get("id"), "")
			}
			bindings, err := find("bindings", core.NewObject("tenantId", tenantID, "subjectType", "identity", "subjectId", id, "roleId", ownerRoleID))
			if err != nil {
				return nil, err
			}
			for _, binding := range bindings {
				if err := tx.Delete(ctx, "bindings", jsString(binding.Get("id"))); err != nil {
					return nil, err
				}
				counts.bindings++
			}
		}
		// Activations are counted before the bindings and memberships that would remove them.
		activations, err := find("bindingActivations", core.NewObject("tenantId", tenantID, "identityId", id))
		if err != nil {
			return nil, err
		}
		for _, activation := range activations {
			if err := tx.Delete(ctx, "bindingActivations", jsString(activation.Get("id"))); err != nil {
				return nil, err
			}
			counts.activations++
		}
		// Package assignments are revoked first, under package ownership: their bindings may come from another
		// administrator's authority, which the generic binding removal below would refuse.
		assignments, err := find("packageAssignments", core.NewObject("tenantId", tenantID, "identityId", id))
		if err != nil {
			return nil, err
		}
		for _, assignment := range assignments {
			removed, err := RevokeAssignment(ctx, server, tx, assignment)
			if err != nil {
				return nil, err
			}
			counts.bindings += int(jsNumber(member(removed, "bindings")))
			counts.memberships += int(jsNumber(member(removed, "memberships")))
			counts.packages++
		}
		bindings, err := find("bindings", core.NewObject("tenantId", tenantID, "subjectType", "identity", "subjectId", id))
		if err != nil {
			return nil, err
		}
		for _, binding := range bindings {
			if err := DeleteBinding(ctx, server, tx, principal, binding); err != nil {
				return nil, err
			}
			counts.bindings++
		}
		// Teams and departments (teams.ts, departments.ts): team memberships go first, taking the team-managed group
		// memberships with them; departments they head pass to the successor. Reported only when non-zero.
		teamsLeft, err := RemoveFromAllTeams(ctx, tx, tenantID, id, server.Now())
		if err != nil {
			return nil, err
		}
		successorID := ""
		if successor != nil {
			successorID = jsString(successor.Get("id"))
		}
		departments, err := ReleaseDepartments(ctx, tx, tenantID, id, server.Now(), successorID)
		if err != nil {
			return nil, err
		}
		orgCounts := core.NewObject()
		if truthy(teamsLeft) {
			orgCounts.Set("teamsLeft", teamsLeft)
		}
		if headsReassigned := member(departments, "headsReassigned"); truthy(headsReassigned) {
			orgCounts.Set("departmentsReassigned", headsReassigned)
		}
		// Seats of the groups' license products are reconciled once, after every membership is gone.
		if _, err := BatchGroupLicenses(ctx, server, tx, func(ctx context.Context) (any, error) {
			memberships, err := find("groupMembers", core.NewObject("tenantId", tenantID, "identityId", id))
			if err != nil {
				return nil, err
			}
			for _, membership := range memberships {
				if err := RemoveGroupMember(ctx, server, tx, principal, core.NewObject(
					"tenantId", tenantID, "groupId", membership.Get("groupId"), "identityId", id,
				)); err != nil {
					return nil, err
				}
				counts.memberships++
			}
			return core.Undefined, nil
		}); err != nil {
			return nil, err
		}
		tuples, err := find("relationships", core.NewObject("tenantId", tenantID, "subjectType", "identity", "subjectId", id))
		if err != nil {
			return nil, err
		}
		for _, tuple := range tuples {
			if err := tx.Delete(ctx, "relationships", jsString(tuple.Get("id"))); err != nil {
				return nil, err
			}
			counts.relationships++
		}
		accessRequests, err := find("accessRequests", core.NewObject("tenantId", tenantID, "requesterId", id, "status", "pending"))
		if err != nil {
			return nil, err
		}
		for _, request := range accessRequests {
			if _, err := tx.Put(ctx, "accessRequests", request.Spread(core.NewObject("status", "cancelled", "reviewedAt", now()))); err != nil {
				return nil, err
			}
			counts.accessRequests++
		}
		packageRequests, err := find("packageRequests", core.NewObject("tenantId", tenantID, "identityId", id, "status", "pending"))
		if err != nil {
			return nil, err
		}
		for _, request := range packageRequests {
			if _, err := tx.Put(ctx, "packageRequests", request.Spread(core.NewObject("status", "cancelled", "decidedAt", now()))); err != nil {
				return nil, err
			}
			counts.accessRequests++
		}
		authorities, err := find("grantAuthorities", core.NewObject("tenantId", tenantID, "identityId", id))
		if err != nil {
			return nil, err
		}
		for _, authority := range authorities {
			if !truthy(authority.Get("revoked")) {
				if _, err := tx.Put(ctx, "grantAuthorities", authority.Spread(core.NewObject("revoked", true))); err != nil {
					return nil, err
				}
				counts.authorities++
			}
		}
		// Their reports move to the successor, or are left without a manager. The successor, if one of them, moves up
		// to the leaver's own manager; a report above the successor in the same line would close a cycle and is left
		// without a manager instead.
		successorLine := map[string]bool{}
		cursor := successor
		for depth := 0; cursor != nil && truthy(cursor.Get("managerId")) && depth < 100; depth++ {
			successorLine[jsString(cursor.Get("managerId"))] = true
			if cursor, err = tx.Get(ctx, "identities", jsString(cursor.Get("managerId"))); err != nil {
				return nil, err
			}
		}
		reports, err := find("identities", core.NewObject("tenantId", tenantID, "managerId", id))
		if err != nil {
			return nil, err
		}
		for _, report := range reports {
			if report.Get("status") == "deleted" {
				continue
			}
			rest := report.Spread()
			rest.Delete("managerId")
			var managerID any = core.Undefined
			switch {
			case successor != nil && core.StrictEquals(report.Get("id"), successor.Get("id")):
				if leaverManager := identity.Get("managerId"); !isUndefined(leaverManager) && !core.StrictEquals(leaverManager, report.Get("id")) {
					managerID = leaverManager
				}
			case successor != nil && !successorLine[jsString(report.Get("id"))]:
				managerID = successor.Get("id")
			}
			if !isUndefined(managerID) {
				rest.Set("managerId", managerID)
			}
			if _, err := tx.Put(ctx, "identities", rest); err != nil {
				return nil, err
			}
			counts.reportsReassigned++
		}
		resources, err := find("resources", core.NewObject("tenantId", tenantID, "ownerId", id))
		if err != nil {
			return nil, err
		}
		for _, resource := range resources {
			if successor != nil {
				if _, err := tx.Put(ctx, "resources", resource.Spread(core.NewObject("ownerId", successor.Get("id"), "updatedAt", now()))); err != nil {
					return nil, err
				}
				counts.resourcesReassigned++
			} else {
				counts.resourcesOwned++
			}
		}
		// AI agents (agents.ts): the agents they sponsor move to the successor, and every delegation they gave (or,
		// for an agent, hold) ends. Reported only when there was something to do, so other results keep their shape.
		reassigned, unsponsored, err := HandOverAgents(ctx, server, tx, principal, identity, successor)
		if err != nil {
			return nil, err
		}
		delegationsRevoked, err := RevokeDelegationsOf(ctx, server, tx, identity, jsString(principal.Identity.Get("id")))
		if err != nil {
			return nil, err
		}
		// Guests (guests.ts): the guests they sponsor move to the successor or are flagged for a new sponsor, and a
		// leaver who is a guest has their guest account closed. Reported only when non-zero, like the agents.
		guestHandover, err := HandOverGuests(ctx, server, tx, principal, identity, successor)
		if err != nil {
			return nil, err
		}
		// Security clearances (clearances.ts): the leaver's clearance is terminated and every compartment debriefed.
		clearancesTerminated, err := TerminateClearancesOf(ctx, server, tx, principal, identity, reason)
		if err != nil {
			return nil, err
		}
		agentCounts := core.NewObject()
		if reassigned != 0 {
			agentCounts.Set("agentsReassigned", float64(reassigned))
		}
		if unsponsored != 0 {
			agentCounts.Set("agentsUnsponsored", float64(unsponsored))
		}
		if truthy(delegationsRevoked) {
			agentCounts.Set("delegationsRevoked", delegationsRevoked)
		}
		if guests := member(guestHandover, "reassigned"); truthy(guests) {
			agentCounts.Set("guestsReassigned", guests)
		}
		if guests := member(guestHandover, "unsponsored"); truthy(guests) {
			agentCounts.Set("guestsUnsponsored", guests)
		}
		if truthy(clearancesTerminated) {
			agentCounts.Set("clearancesTerminated", clearancesTerminated)
		}
		if err := server.RevokeAll(ctx, tx, id); err != nil {
			return nil, err
		}
		if err := RevokeInvitationsBy(ctx, tx, id); err != nil {
			return nil, err
		}
		disabled, err := tx.Put(ctx, "identities", identity.Spread(core.NewObject("status", "disabled", "owner", false)))
		if err != nil {
			return nil, err
		}
		// An offboarded identity stays disabled: a threats containment of it can no longer be released.
		if err := EndContainment(ctx, tx, id, server.Now()); err != nil {
			return nil, err
		}
		metadata := core.NewObject("reason", reason, "kind", identity.Get("kind"))
		if successor != nil {
			metadata.Set("successorId", successor.Get("id"))
		}
		metadata.Assign(counts.model(), agentCounts, orgCounts)
		if err := server.Events.Audit(ctx, tx, principal, "identity:offboard", tenantID, id, "allow", false, metadata); err != nil {
			return nil, err
		}
		return core.NewObject("identity", PublicIdentity(disabled)).Assign(counts.model(), agentCounts, orgCounts), nil
	}, false)
	// A disabled identity claims no license seat: reconciling releases its seats (licenses.ts).
	result, err := identityAfterChange(ctx, server, rawTenantID, []string{jsString(identityID)}, outcome, err)
	return Out[apitypes.IdentitiesOffboardOutput]{Value: result}, err
}

// Update is POST {basePath}/identities/update. Renames an identity, replaces its declared attributes (validated
// against `permissions.identityAttributes`), changes its email, or schedules/clears its deactivation (`expiresAt`,
// null to clear). An email change requires recent authentication, marks the address unverified, revokes the
// identity's sessions, and is audited as `identity:email-change`. Changing the expiry of an owner or root
// administrator needs the same protection as disabling them (an owner or root caller), the last owner without an
// expiry cannot be given one, and shortening it to the past is refused (disable the identity instead). Changing your
// own attributes, manager, or expiry needs an owner or root caller.
func (api *IdentitiesAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesUpdateInput]) (Out[apitypes.IdentitiesUpdateOutput], error) {
	server := api.server
	tenantID, identityID := input.Get("tenantId"), input.Get("identityId")
	updated, err := Operate(ctx, server.Operations, credential, tenantID, "iam:identities:update", jsString(identityID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		identity, err := server.ActiveIdentity(ctx, tx, identityID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		name, attributes, email := input.Get("name"), input.Get("attributes"), input.Get("email")
		expiresAt, managerID := input.Get("expiresAt"), input.Get("managerId")
		if isUndefined(name) && isUndefined(attributes) && isUndefined(email) && isUndefined(expiresAt) && isUndefined(managerID) {
			return nil, invalidInput("Nothing to update")
		}
		next := identity.Spread()
		if !isUndefined(name) {
			text, err := Text(name, "name")
			if err != nil {
				return nil, err
			}
			next.Set("name", text)
		}
		if !isUndefined(attributes) {
			values, err := AttributeValues(server.Catalog.IdentityAttributes, attributes)
			if err != nil {
				return nil, err
			}
			next.Set("attributes", values)
		}
		if !isUndefined(expiresAt) {
			if err := identityRootProtected(ctx, server, tx, principal, identity); err != nil {
				return nil, err
			}
			if err := AssertOwnerControl(ctx, server, tx, principal, identity, "Only an owner can change an owner’s expiry"); err != nil {
				return nil, err
			}
			if expiresAt == nil {
				next.Delete("expiresAt")
			} else {
				if truthy(identity.Get("owner")) {
					if err := server.ProtectLastOwner(ctx, tx, identity); err != nil {
						return nil, err
					}
					// An owner past their expiry is locked out like a disabled one: the last owner without an expiry
					// keeps none, or every owner could be scheduled away with nobody left to undo it.
					if _, scheduled := identity.Get("expiresAt").(float64); !scheduled {
						owners, err := tx.Find(ctx, "identities", core.NewObject("tenantId", identity.Get("tenantId"), "owner", true, "status", "active"), nil)
						if err != nil {
							return nil, err
						}
						another := false
						for _, other := range owners {
							if _, otherScheduled := other.Get("expiresAt").(float64); !core.StrictEquals(other.Get("id"), identity.Get("id")) && !otherScheduled {
								another = true
								break
							}
						}
						if !another {
							return nil, core.NewIamError("LAST_OWNER", "The last owner without an expiry cannot be given one", 409)
						}
					}
				}
				expiry, err := server.BindingExpiry(expiresAt)
				if err != nil {
					return nil, err
				}
				next.Set("expiresAt", expiry)
			}
		}
		if managerID == nil {
			next.Delete("managerId")
		} else if !isUndefined(managerID) && !core.StrictEquals(managerID, identity.Get("managerId")) {
			manager, err := managerFor(ctx, server, tx, identity, managerID)
			if err != nil {
				return nil, err
			}
			next.Set("managerId", manager)
		}
		// Attributes, the reporting line and the expiry feed birthright package rules and policy conditions, so
		// changing your own would grant you access: only an owner of the tenant or root may. Re-sending the current
		// values is not a change.
		if core.StrictEquals(identity.Get("id"), principal.Identity.Get("id")) &&
			(!sameAttributes(next.Get("attributes"), identity.Get("attributes")) ||
				!core.StrictEquals(next.Get("managerId"), identity.Get("managerId")) ||
				!core.StrictEquals(next.Get("expiresAt"), identity.Get("expiresAt"))) {
			allowed, err := identityOwnerOrRoot(ctx, server, tx, principal, tenantID)
			if err != nil {
				return nil, err
			}
			if !allowed {
				return nil, NewOperationDenied("Your own attributes, manager and expiry are changed by another administrator")
			}
		}
		var previousEmail any = core.Undefined
		if !isUndefined(email) {
			if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
				return nil, err
			}
			if identity.Get("kind") != "user" {
				return nil, invalidInput("Service accounts have no email")
			}
			address, err := Email(email)
			if err != nil {
				return nil, err
			}
			if !core.StrictEquals(address, identity.Get("email")) {
				// A guest's address is the one their invitation proved and the cross-tenant settings admitted
				// (guests.ts).
				if truthy(identity.Get("guest")) {
					return nil, invalidInput("A guest’s email address cannot change: invite the new address instead")
				}
				if err := assertAccountControl(ctx, server, tx, principal, identity); err != nil {
					return nil, err
				}
				holders, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "email", address), nil)
				if err != nil {
					return nil, err
				}
				for _, other := range holders {
					if !core.StrictEquals(other.Get("id"), identity.Get("id")) {
						return nil, core.NewIamError("IDENTITY_EXISTS", "Email is already in use in this tenant", 409)
					}
				}
				previousEmail = identity.Get("email")
				next.Set("email", address)
				next.Set("uniqueKey", "email:"+address)
				next.Set("emailVerified", false)
			}
		}
		stored, err := tx.Put(ctx, "identities", next)
		if err != nil {
			return nil, err
		}
		if !isUndefined(previousEmail) || (!isUndefined(email) && !truthy(identity.Get("email"))) {
			if err := server.RevokeAll(ctx, tx, jsString(identity.Get("id"))); err != nil {
				return nil, err
			}
			if err := server.Events.Audit(ctx, tx, principal, "identity:email-change", jsString(tenantID), jsString(identity.Get("id")), "allow", false,
				core.NewObject("from", coalesce(previousEmail, nil), "to", coalesce(stored.Get("email"), nil))); err != nil {
				return nil, err
			}
		}
		return PublicIdentity(stored), nil
	}, false)
	var ids []string
	if updated != nil {
		ids = []string{jsString(updated.Get("id"))}
	}
	result, err := identityAfterChange(ctx, server, tenantID, ids, updated, err)
	return Out[apitypes.IdentitiesUpdateOutput]{Value: result}, err
}

// Delete is POST {basePath}/identities/delete. Removes a person or service account. Requires recent authentication
// and iam:identities:delete; the last owner and last root administrator are protected.
func (api *IdentitiesAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesDeleteInput]) (Out[apitypes.IdentitiesDeleteOutput], error) {
	server := api.server
	tenantID, identityID := input.Get("tenantId"), input.Get("identityId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:identities:delete", jsString(identityID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		identity, err := server.Scoped(ctx, tx, "identities", identityID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		deleted, err := DeleteIdentity(ctx, server, tx, principal, identity)
		if err != nil {
			return nil, err
		}
		metadata := core.NewObject("kind", identity.Get("kind"))
		if email := identity.Get("email"); truthy(email) {
			metadata.Set("email", email)
		}
		if err := server.Events.Audit(ctx, tx, principal, "identity:delete", jsString(tenantID), jsString(identity.Get("id")), "allow", false, metadata); err != nil {
			return nil, err
		}
		return deleted, nil
	}, false)
	return Out[apitypes.IdentitiesDeleteOutput]{Value: result}, err
}

// ListReports is POST {basePath}/identities/listReports: the active identities that report to this one
// (`managerId`), by name. Requires iam:identities:read.
func (api *IdentitiesAPI) ListReports(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesListReportsInput]) (Out[apitypes.IdentitiesListReportsOutput], error) {
	server := api.server
	tenantID, identityID := input.Get("tenantId"), input.Get("identityId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:identities:read", jsString(identityID), func(ctx context.Context, call MutationContext) ([]any, error) {
		if _, err := server.Scoped(ctx, call.Tx, "identities", identityID, jsString(tenantID)); err != nil {
			return nil, err
		}
		reports, err := call.Tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "managerId", identityID), nil)
		if err != nil {
			return nil, err
		}
		active := []*core.Object{}
		for _, report := range reports {
			if report.Get("status") == "active" {
				active = append(active, report)
			}
		}
		identitySortByName(active)
		list := make([]any, len(active))
		for index, report := range active {
			list[index] = PublicIdentity(report)
		}
		return list, nil
	}, false)
	return Out[apitypes.IdentitiesListReportsOutput]{Value: result}, err
}

// ListGroups is POST {basePath}/identities/listGroups: current groups of an identity (expired memberships omitted),
// each with `membershipExpiresAt` when temporary.
func (api *IdentitiesAPI) ListGroups(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesListGroupsInput]) (Out[apitypes.IdentitiesListGroupsOutput], error) {
	server := api.server
	tenantID, identityID := input.Get("tenantId"), input.Get("identityId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:groups:read", jsString(identityID), func(ctx context.Context, call MutationContext) ([]any, error) {
		tx := call.Tx
		if _, err := server.Scoped(ctx, tx, "identities", identityID, jsString(tenantID)); err != nil {
			return nil, err
		}
		memberships, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
		if err != nil {
			return nil, err
		}
		groups := []any{}
		for _, membership := range memberships {
			if !server.LiveMembership(membership) {
				continue
			}
			group, err := tx.Get(ctx, "groups", jsString(membership.Get("groupId")))
			if err != nil {
				return nil, err
			}
			if group != nil && core.StrictEquals(group.Get("tenantId"), tenantID) {
				entry := group.Spread()
				if expiresAt := membership.Get("expiresAt"); !isUndefined(expiresAt) {
					entry.Set("membershipExpiresAt", expiresAt)
				}
				groups = append(groups, entry)
			}
		}
		return groups, nil
	}, false)
	return Out[apitypes.IdentitiesListGroupsOutput]{Value: result}, err
}

// ListBindings is POST {basePath}/identities/listBindings: direct and group-derived role bindings, the effective role
// set of an identity.
func (api *IdentitiesAPI) ListBindings(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesListBindingsInput]) (Out[apitypes.IdentitiesListBindingsOutput], error) {
	server := api.server
	tenantID, identityID := input.Get("tenantId"), input.Get("identityId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:bindings:read", jsString(identityID), func(ctx context.Context, call MutationContext) ([]any, error) {
		if _, err := server.Scoped(ctx, call.Tx, "identities", identityID, jsString(tenantID)); err != nil {
			return nil, err
		}
		effective, err := server.Decisions.EffectiveBindings(ctx, call.Tx, jsString(tenantID), jsString(identityID))
		if err != nil {
			return nil, err
		}
		list := make([]any, len(effective))
		for index, binding := range effective {
			list[index] = binding.Model()
		}
		return list, nil
	}, false)
	return Out[apitypes.IdentitiesListBindingsOutput]{Value: result}, err
}

// identityInvitationMail queues the sealed member-invitation email of an invitation token.
func identityInvitationMail(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, realm *core.Object, to any, inviteToken string, now float64) error {
	outboxID := ID()
	payload, _, err := core.Stringify(core.NewObject(
		"token", inviteToken,
		"tenantId", realm.Get("id"),
		"tenantName", realm.Get("name"),
		"inviterName", principal.Identity.Get("name"),
	))
	if err != nil {
		return err
	}
	_, err = tx.Insert(ctx, "outbox", core.NewObject(
		"id", outboxID,
		"tenantId", realm.Get("id"),
		"kind", "email",
		"to", to,
		"template", "member-invitation",
		"payload", core.NewObject("sealed", auth.EncryptSecret(payload, server.Options.Secret, "outbox:"+outboxID)),
		"createdAt", now,
		"attempts", 0.0,
	))
	return err
}

// invitationsDeliverable is `options.authentication?.sendEmail`.
func invitationsDeliverable(server *ServerContext) bool {
	return server.Options.Authentication != nil && server.Options.Authentication.SendEmail != nil
}

// Invite is POST {basePath}/identities/invite. Invites a person into an existing tenant. Roles and groups are applied
// when the invitation is accepted, under the inviter's authority; groups a license product is assigned to need
// iam:licenses:assign, now and at acceptance.
func (api *IdentitiesAPI) Invite(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesInviteInput]) (Out[apitypes.IdentitiesInviteOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:identities:create", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, realm := call.Tx, call.Principal, call.Tenant
		if !invitationsDeliverable(server) {
			return nil, core.NewIamError("DELIVERY_REQUIRED", "Member invitations require an email delivery callback")
		}
		if realm.Get("status") != "active" {
			return nil, core.NewIamError("TENANT_INACTIVE", "Tenant must be active")
		}
		realmID := jsString(realm.Get("id"))
		to, err := Email(input.Get("email"))
		if err != nil {
			return nil, err
		}
		existing, err := tx.Find(ctx, "identities", core.NewObject("tenantId", realmID, "email", to), nil)
		if err != nil {
			return nil, err
		}
		if len(existing) > 0 {
			return nil, core.NewIamError("IDENTITY_EXISTS", "An identity with this email already exists in this tenant", 409)
		}
		roleIDs, err := Strings(coalesce(input.Get("roleIds"), []any{}), "roleIds")
		if err != nil {
			return nil, err
		}
		groupIDs, err := Strings(coalesce(input.Get("groupIds"), []any{}), "groupIds")
		if err != nil {
			return nil, err
		}
		var authorityID any = core.Undefined
		if len(roleIDs) > 0 || len(groupIDs) > 0 {
			authority, err := server.GrantingAuthority(ctx, tx, principal, realmID, "")
			if err != nil {
				return nil, err
			}
			authorityID = authority.Get("id")
		}
		if err := identityGrantChecks(ctx, server, tx, principal, realmID, roleIDs, groupIDs); err != nil {
			return nil, err
		}
		// The invitee claims the seats of licensed groups: iam:licenses:assign, checked again at acceptance
		// (flows.ts).
		if err := AssertMayClaimLicenses(ctx, server, tx, principal, realmID, stringsOf(groupIDs), identitySeatsMessage); err != nil {
			return nil, err
		}
		inviteToken := Token()
		now := float64(server.Wall())
		invitation := core.NewObject(
			"id", ID(),
			"tenantId", realmID,
			"email", to,
			"tokenHash", Hash(inviteToken),
			"uniqueKey", Hash(inviteToken),
			"roleIds", stringsOf(roleIDs),
			"groupIds", stringsOf(groupIDs),
			"inviterId", principal.Identity.Get("id"),
			"createdAt", now,
			"expiresAt", now+server.Config.InvitationLifetimeMs,
			"consumed", false,
		)
		if !isUndefined(input.Get("name")) {
			name, err := Text(input.Get("name"), "name")
			if err != nil {
				return nil, err
			}
			invitation.Set("name", name)
		}
		if !isUndefined(authorityID) {
			invitation.Set("authorityId", authorityID)
		}
		if _, err := tx.Insert(ctx, "memberInvitations", invitation); err != nil {
			return nil, err
		}
		if err := identityInvitationMail(ctx, server, tx, principal, realm, to, inviteToken, now); err != nil {
			return nil, err
		}
		return core.NewObject(
			"invitationId", invitation.Get("id"),
			"email", to,
			"expiresAt", invitation.Get("expiresAt"),
			"roleIds", stringsOf(roleIDs),
			"groupIds", stringsOf(groupIDs),
		), nil
	}, false)
	return Out[apitypes.IdentitiesInviteOutput]{Value: result}, err
}

// ListInvitations is POST {basePath}/identities/listInvitations. Lists every member invitation of the tenant, pending
// or not, without tokens.
func (api *IdentitiesAPI) ListInvitations(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesListInvitationsInput]) (Out[apitypes.IdentitiesListInvitationsOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:identities:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		invitations, err := call.Tx.Find(ctx, "memberInvitations", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		list := make([]any, len(invitations))
		for index, invitation := range invitations {
			list[index] = identityWithoutTokenHash(invitation)
		}
		return list, nil
	}, false)
	return Out[apitypes.IdentitiesListInvitationsOutput]{Value: result}, err
}

// RevokeInvitation is POST {basePath}/identities/revokeInvitation. Cancels a member invitation so its link can no
// longer be used.
func (api *IdentitiesAPI) RevokeInvitation(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesRevokeInvitationInput]) (Out[apitypes.IdentitiesRevokeInvitationOutput], error) {
	server := api.server
	tenantID, invitationID := input.Get("tenantId"), input.Get("invitationId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:identities:update", jsString(invitationID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		invitation, err := server.Scoped(ctx, call.Tx, "memberInvitations", invitationID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		if truthy(invitation.Get("consumed")) || truthy(invitation.Get("revoked")) {
			return nil, core.NewIamError("CONFLICT", "Invitation is already consumed or revoked", 409)
		}
		stored, err := call.Tx.Put(ctx, "memberInvitations", invitation.Spread(core.NewObject("revoked", true)))
		if err != nil {
			return nil, err
		}
		return identityWithoutTokenHash(stored), nil
	}, false)
	return Out[apitypes.IdentitiesRevokeInvitationOutput]{Value: result}, err
}

// ResendInvitation is POST {basePath}/identities/resendInvitation. Re-sends a member invitation with a fresh token
// and lifetime; the earlier token stops working. Only an invitation that can still be accepted goes out: its inviter
// must still grant what it grants, as acceptance checks again (INVITATION_INVALID; revoke it and invite the person
// again).
func (api *IdentitiesAPI) ResendInvitation(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesResendInvitationInput]) (Out[apitypes.IdentitiesResendInvitationOutput], error) {
	server := api.server
	tenantID, invitationID := input.Get("tenantId"), input.Get("invitationId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:identities:update", jsString(invitationID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, realm := call.Tx, call.Principal, call.Tenant
		if !invitationsDeliverable(server) {
			return nil, core.NewIamError("DELIVERY_REQUIRED", "Member invitations require an email delivery callback")
		}
		if realm.Get("status") != "active" {
			return nil, core.NewIamError("TENANT_INACTIVE", "Tenant must be active")
		}
		invitation, err := server.Scoped(ctx, tx, "memberInvitations", invitationID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		if truthy(invitation.Get("consumed")) || truthy(invitation.Get("revoked")) {
			return nil, core.NewIamError("CONFLICT", "Invitation is already consumed or revoked", 409)
		}
		// Acceptance would refuse an invitation its inviter can no longer grant (flows.ts): send none.
		if err := AssertMemberInvitationGrantable(ctx, server, tx, invitation, jsString(realm.Get("id"))); err != nil {
			iamErr, ok := asIamError(err)
			if !ok || iamErr.Code != "INVITATION_INVALID" {
				return nil, err
			}
			return nil, core.NewIamError("INVITATION_INVALID", iamErr.Message+": revoke this invitation and invite the person again")
		}
		inviteToken := Token()
		now := float64(server.Wall())
		renewed, err := tx.Put(ctx, "memberInvitations", invitation.Spread(core.NewObject(
			"tokenHash", Hash(inviteToken),
			"uniqueKey", Hash(inviteToken),
			"expiresAt", now+server.Config.InvitationLifetimeMs,
		)))
		if err != nil {
			return nil, err
		}
		if err := identityInvitationMail(ctx, server, tx, principal, realm, invitation.Get("email"), inviteToken, now); err != nil {
			return nil, err
		}
		return core.NewObject("invitationId", renewed.Get("id"), "email", renewed.Get("email"), "expiresAt", renewed.Get("expiresAt")), nil
	}, false)
	return Out[apitypes.IdentitiesResendInvitationOutput]{Value: result}, err
}

// AcceptInvitation is POST {basePath}/identities/acceptInvitation (public: no request credential). Redeems a member
// invitation: creates the person's account with the invited email, applies the invitation's roles and groups, and
// signs them in.
func (api *IdentitiesAPI) AcceptInvitation(ctx context.Context, input In[apitypes.IdentitiesAcceptInvitationInput]) (Out[apitypes.IdentitiesAcceptInvitationOutput], error) {
	body := input.Body
	if body == nil {
		body = core.NewObject()
	}
	result, err := api.server.Flows.AcceptMemberInvitation(ctx, body)
	if err != nil {
		return Out[apitypes.IdentitiesAcceptInvitationOutput]{}, err
	}
	return Out[apitypes.IdentitiesAcceptInvitationOutput]{Value: result}, nil
}

// SetStatus is POST {basePath}/identities/setStatus. Disables (ending its sessions, keys and pending invitations) or
// re-enables an identity. Disabling an owner needs an owner or root caller; agents are stopped and restarted with
// `agents.suspend` and `agents.resume` instead.
func (api *IdentitiesAPI) SetStatus(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesSetStatusInput]) (Out[apitypes.IdentitiesSetStatusOutput], error) {
	server := api.server
	tenantID, identityID := input.Get("tenantId"), input.Get("identityId")
	updated, err := Operate(ctx, server.Operations, credential, tenantID, "iam:identities:update", jsString(identityID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		status := input.Get("status")
		if status != "active" && status != "disabled" {
			return nil, invalidInput("Invalid identity status")
		}
		identity, err := server.ActiveIdentity(ctx, tx, identityID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		// An agent's status follows its own rules (agents.ts): re-enabling it here would lift a suspension that only
		// agents.resume, with its own permission and recent sign-in, may lift.
		if identity.Get("kind") == "agent" {
			return nil, invalidInput("Use agents.suspend and agents.resume to stop or restart an agent")
		}
		if err := identityRootProtected(ctx, server, tx, principal, identity); err != nil {
			return nil, err
		}
		if status == "disabled" {
			if err := AssertOwnerControl(ctx, server, tx, principal, identity, "Only an owner can disable an owner"); err != nil {
				return nil, err
			}
			if err := server.ProtectLastOwner(ctx, tx, identity); err != nil {
				return nil, err
			}
		}
		if status == "active" && server.IdentityExpired(identity) {
			return nil, core.NewIamError("INVALID_TRANSITION", "Extend or clear expiresAt before re-enabling an expired identity", 409)
		}
		stored, err := tx.Put(ctx, "identities", identity.Spread(core.NewObject("status", status)))
		if err != nil {
			return nil, err
		}
		id := jsString(identity.Get("id"))
		// The status is now this call's: a threats containment is over (released here, or held by this disable).
		if err := EndContainment(ctx, tx, id, server.Now()); err != nil {
			return nil, err
		}
		if status == "disabled" {
			if err := server.RevokeAll(ctx, tx, id); err != nil {
				return nil, err
			}
			if err := RevokeInvitationsBy(ctx, tx, id); err != nil {
				return nil, err
			}
		}
		return PublicIdentity(stored), nil
	}, false)
	var ids []string
	if updated != nil {
		ids = []string{jsString(updated.Get("id"))}
	}
	result, err := identityAfterChange(ctx, server, tenantID, ids, updated, err)
	return Out[apitypes.IdentitiesSetStatusOutput]{Value: result}, err
}

// SetOwner is POST {basePath}/identities/setOwner. Ownership transfer: grants or removes the protected Owner role;
// the last active owner is protected. A former owner's owner grant authority passes to a remaining owner, so what
// they granted stays and they grant no more.
func (api *IdentitiesAPI) SetOwner(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesSetOwnerInput]) (Out[apitypes.IdentitiesSetOwnerOutput], error) {
	server := api.server
	rawTenantID, identityID := input.Get("tenantId"), input.Get("identityId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:identities:update", jsString(identityID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		tenantID := jsString(rawTenantID)
		allowed, err := identityOwnerOrRoot(ctx, server, tx, principal, tenantID)
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, core.NewIamError("ACCESS_DENIED", "Only an owner can transfer ownership", 403)
		}
		identity, err := server.ActiveIdentity(ctx, tx, identityID, tenantID)
		if err != nil {
			return nil, err
		}
		owner, isBool := input.Get("owner").(bool)
		if identity.Get("kind") != "user" || identity.Get("status") != "active" || !isBool {
			return nil, invalidInput("Invalid owner")
		}
		if !owner {
			if err := server.ProtectLastOwner(ctx, tx, identity); err != nil {
				return nil, err
			}
		}
		ownerRoles, err := tx.Find(ctx, "roles", core.NewObject("tenantId", tenantID, "uniqueKey", "system:owner"), nil)
		if err != nil {
			return nil, err
		}
		if len(ownerRoles) == 0 {
			return nil, core.NewIamError("NOT_FOUND", "Owner role missing", 404)
		}
		ownerRole := ownerRoles[0]
		id := jsString(identity.Get("id"))
		if owner && !truthy(identity.Get("owner")) {
			parent, err := server.GrantingAuthority(ctx, tx, principal, tenantID, "")
			if err != nil {
				return nil, err
			}
			authority, err := tx.Insert(ctx, "grantAuthorities", core.NewObject(
				"id", ID(),
				"tenantId", tenantID,
				"identityId", id,
				"ceiling", All(),
				"parentAuthorityId", parent.Get("id"),
				"revoked", false,
			))
			if err != nil {
				return nil, err
			}
			if _, err := tx.Insert(ctx, "bindings", core.NewObject(
				"id", ID(),
				"tenantId", tenantID,
				"subjectType", "identity",
				"subjectId", id,
				"roleId", ownerRole.Get("id"),
				"authorityId", authority.Get("id"),
			)); err != nil {
				return nil, err
			}
		}
		if !owner {
			// The unlimited grant authority the Owner role came with (from setOwner or the owner invitation) leaves
			// the former owner too. It passes to an owner who stays (the caller, or else the longest-standing other
			// owner) instead of being revoked: revoking it would also end every grant made under it, including the
			// authorities of owners promoted through it.
			var successorID any = core.Undefined
			if ownsTenant(principal, tenantID) && !core.StrictEquals(principal.Identity.Get("id"), identity.Get("id")) {
				successorID = principal.Identity.Get("id")
			} else {
				owners, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "owner", true, "status", "active"), nil)
				if err != nil {
					return nil, err
				}
				others := []*core.Object{}
				for _, other := range owners {
					if !core.StrictEquals(other.Get("id"), identity.Get("id")) {
						others = append(others, other)
					}
				}
				sort.SliceStable(others, func(i, j int) bool {
					left, _ := others[i].Get("createdAt").(float64)
					right, _ := others[j].Get("createdAt").(float64)
					if difference := left - right; difference != 0 && difference == difference {
						return difference < 0
					}
					return ByID(others[i], others[j]) < 0
				})
				if len(others) > 0 {
					successorID = others[0].Get("id")
				}
			}
			bindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "identity", "subjectId", id, "roleId", ownerRole.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			for _, binding := range bindings {
				if err := tx.Delete(ctx, "bindings", jsString(binding.Get("id"))); err != nil {
					return nil, err
				}
				authority, err := tx.Get(ctx, "grantAuthorities", jsString(binding.Get("authorityId")))
				if err != nil {
					return nil, err
				}
				if authority != nil && core.StrictEquals(authority.Get("identityId"), identity.Get("id")) && !isUndefined(successorID) {
					if _, err := tx.Put(ctx, "grantAuthorities", authority.Spread(core.NewObject("identityId", successorID))); err != nil {
						return nil, err
					}
				}
			}
		}
		stored, err := tx.Put(ctx, "identities", identity.Spread(core.NewObject("owner", owner)))
		if err != nil {
			return nil, err
		}
		return PublicIdentity(stored), nil
	}, false)
	return Out[apitypes.IdentitiesSetOwnerOutput]{Value: result}, err
}

// SetBoundary is POST {basePath}/identities/setBoundary. Sets a root-controlled permissions boundary on one
// identity, capping what it may do in the tenant whatever its roles grant.
func (api *IdentitiesAPI) SetBoundary(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesSetBoundaryInput]) (Out[apitypes.IdentitiesSetBoundaryOutput], error) {
	server := api.server
	rawTenantID, identityID := input.Get("tenantId"), input.Get("identityId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:boundaries:update", jsString(identityID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(rawTenantID)
		document := input.Get("document")
		if err := server.Catalog.Validate(ctx, tx, tenantID, document); err != nil {
			return nil, err
		}
		if _, err := server.Scoped(ctx, tx, "identities", identityID, tenantID); err != nil {
			return nil, err
		}
		root, err := server.RootPrincipal(ctx, tx, principal)
		if err != nil {
			return nil, err
		}
		if !root {
			return nil, core.NewIamError("ACCESS_DENIED", "Principal ceilings are platform controlled", 403)
		}
		existing, err := tx.Find(ctx, "principalBoundaries", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
		if err != nil {
			return nil, err
		}
		var recordID any = core.Undefined
		if len(existing) > 0 {
			recordID = existing[0].Get("id")
		}
		record := core.NewObject(
			"id", coalesce(recordID, ID()),
			"tenantId", tenantID,
			"uniqueKey", identityID,
			"identityId", identityID,
			"document", document,
		)
		if len(existing) > 0 {
			return tx.Put(ctx, "principalBoundaries", record)
		}
		return tx.Insert(ctx, "principalBoundaries", record)
	}, false)
	return Out[apitypes.IdentitiesSetBoundaryOutput]{Value: result}, err
}
