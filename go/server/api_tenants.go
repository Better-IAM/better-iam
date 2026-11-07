package server

// Port of packages/server/src/api/tenants.ts: the `tenants` API group (the tenant hierarchy, owner invitations,
// sign-in discovery, regions, and the per-tenant authentication, access, and plan policies).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// TenantsAPI is the `tenants` API group (packages/server/src/api/tenants.ts createTenantsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/tenants/{method} onto it.
type TenantsAPI struct {
	server *ServerContext
}

// CreateTenantsAPI builds the `tenants` API group.
func CreateTenantsAPI(server *ServerContext) *TenantsAPI {
	return &TenantsAPI{server: server}
}

// stricterLimits is, per key, the stricter of two sets of plan limits (a key either one sets applies); nil when
// neither sets any. A missing side counts as no limits (`= {}`).
func stricterLimits(a, b any) *core.Object {
	merged := core.NewObject()
	if left, ok := a.(*core.Object); ok {
		merged.Assign(left)
	}
	if right, ok := b.(*core.Object); ok {
		right.Entries(func(key string, value any) bool {
			if isUndefined(value) {
				return true
			}
			if current := merged.Get(key); isUndefined(current) || jsLess(value, current) {
				merged.Set(key, value)
			}
			return true
		})
	}
	if merged.Len() == 0 {
		return nil
	}
	return merged
}

// jsLess is JavaScript `a < b` for the values plan limits hold (two strings compare as strings, anything else as
// numbers).
func jsLess(a, b any) bool {
	left, leftString := a.(string)
	right, rightString := b.(string)
	if leftString && rightString {
		return compareUTF16(left, right) < 0
	}
	return jsNumber(a) < jsNumber(b)
}

// allowsChild is `hierarchy.types[parentType]?.allowedChildren.includes(childType)`.
func (api *TenantsAPI) allowsChild(parentType, childType any) bool {
	name, ok := parentType.(string)
	if !ok {
		return false
	}
	for _, entry := range api.server.Config.Hierarchy.Types {
		if entry.Name != name {
			continue
		}
		for _, child := range entry.Type.AllowedChildren {
			if child == childType {
				return true
			}
		}
		return false
	}
	return false
}

// authorityIDOf is the optional `authorityId` of a request as grantingAuthority reads it: a falsy value picks the
// principal's own authority; any other value is a record ID, validated the way ctx.scoped validates it.
func authorityIDOf(value any) (string, error) {
	if !truthy(value) {
		return "", nil
	}
	return Text(value, "id")
}

// withoutInvitationSecrets drops the token hash of an owner invitation (`{ tokenHash, uniqueKey, ...safe }`).
func withoutInvitationSecrets(invitation *core.Object) *core.Object {
	safe := invitation.Spread()
	safe.Delete("tokenHash")
	safe.Delete("uniqueKey")
	return safe
}

// requireInvitationDelivery refuses when no email delivery callback is configured.
func (api *TenantsAPI) requireInvitationDelivery() error {
	if authentication := api.server.Options.Authentication; authentication == nil || authentication.SendEmail == nil {
		return core.NewIamError("DELIVERY_REQUIRED", "Organization invitations require an email delivery callback")
	}
	return nil
}

// queueOwnerInvitation writes the sealed `owner-invitation` email for a tenant's owner to the outbox.
func (api *TenantsAPI) queueOwnerInvitation(ctx context.Context, tx core.IamStore, realm *core.Object, to any, inviteToken string, now float64) error {
	outboxID := ID()
	sealed := core.MustStringify(core.NewObject("token", inviteToken, "tenantId", realm.Get("id"), "tenantName", realm.Get("name")))
	_, err := tx.Insert(ctx, "outbox", core.NewObject(
		"id", outboxID, "tenantId", realm.Get("id"), "kind", "email", "to", to, "template", "owner-invitation",
		"payload", core.NewObject("sealed", auth.EncryptSecret(sealed, api.server.Options.Secret, "outbox:"+outboxID)),
		"createdAt", now, "attempts", 0.0,
	))
	return err
}

// discovery is what a sign-in screen learns about an organization: who it is and where it signs in.
func (api *TenantsAPI) discovery(ctx context.Context, tx core.IamStore, realm *core.Object) (*core.Object, error) {
	hosts := api.server.Hosts
	region, err := hosts.RegionOf(ctx, tx, realm)
	if err != nil {
		return nil, err
	}
	signInURL, err := hosts.SignInURL(ctx, realm, tx)
	if err != nil {
		return nil, err
	}
	result := core.NewObject("tenantId", realm.Get("id"), "name", realm.Get("name"), "type", realm.Get("type"),
		"slug", coalesce(realm.Get("slug"), ""))
	if region != "" {
		result.Set("region", region)
	}
	if signInURL != "" {
		result.Set("signInUrl", signInURL)
	}
	return result, nil
}

// someInactive is `ancestry.some((item) => item.status !== 'active')`.
func someInactive(ancestry []*core.Object) bool {
	for _, item := range ancestry {
		if item.Get("status") != "active" {
			return true
		}
	}
	return false
}

// rejectDeleted refuses to update a deleted tenant.
func rejectDeleted(target *core.Object) error {
	if target.Get("status") == "deleted" {
		return core.NewIamError("INVALID_TRANSITION", "Deleted tenants cannot be updated")
	}
	return nil
}

// regionOrNull is a home region for audit metadata (`region ?? null`).
func regionOrNull(region string) any {
	if region == "" {
		return nil
	}
	return region
}

// recordsOf converts records into a model array.
func recordsOf(records []*core.Object) []any {
	result := make([]any, 0, len(records))
	for _, record := range records {
		result = append(result, record)
	}
	return result
}

// descendantsOf is the IDs of target and every tenant below it among realms, found level by level up to maxDepth.
func descendantsOf(realms []*core.Object, targetID string, maxDepth int) map[string]bool {
	below := map[string]bool{targetID: true}
	for depth := 0; depth < maxDepth; depth++ {
		for _, realm := range realms {
			if parentID := realm.Get("parentId"); truthy(parentID) && below[jsString(parentID)] {
				below[jsString(realm.Get("id"))] = true
			}
		}
	}
	return below
}

// AcceptInvitation is POST {basePath}/tenants/acceptInvitation (public: no request credential). Redeems an owner invitation: creates the first owner of a pending tenant, activates the tenant, and signs the owner in.
func (api *TenantsAPI) AcceptInvitation(ctx context.Context, input In[apitypes.TenantsAcceptInvitationInput]) (Out[apitypes.TenantsAcceptInvitationOutput], error) {
	body := input.Body
	if body == nil {
		body = core.NewObject()
	}
	result, err := api.server.Flows.AcceptOwnerInvitation(ctx, body)
	if err != nil {
		return Out[apitypes.TenantsAcceptInvitationOutput]{}, err
	}
	return Out[apitypes.TenantsAcceptInvitationOutput]{Value: result}, nil
}

// Create is POST {basePath}/tenants/create. Creates a child tenant in the pending state under a parent and emails an
// invitation to its first owner; the creator's grant authority becomes the parent of the owner's. With
// `activate: true` (root principals only) the tenant is active at once and its owner account is created without an
// invitation, audited as `tenant:activate`.
func (api *TenantsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsCreateInput]) (Out[apitypes.TenantsCreateOutput], error) {
	server := api.server
	config := server.Config
	parentID := input.Get("parentId")
	result, err := Operate(ctx, server.Operations, credential, parentID, "iam:tenants:create", jsString(parentID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, parent := call.Tx, call.Principal, call.Tenant
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		kind, err := Text(input.Get("type"), "type")
		if err != nil {
			return nil, err
		}
		name, err := Text(input.Get("name"), "name")
		if err != nil {
			return nil, err
		}
		ownerEmail, err := Email(input.Get("ownerEmail"))
		if err != nil {
			return nil, err
		}
		for _, field := range []string{"activate", "ownerEmailVerified"} {
			if value := input.Get(field); !isUndefined(value) && typeOf(value) != "boolean" {
				return nil, invalidInput(field + " must be a boolean")
			}
		}
		activate := input.Get("activate") == true
		if !activate && (!isUndefined(input.Get("ownerName")) || !isUndefined(input.Get("ownerEmailVerified"))) {
			return nil, invalidInput("ownerName and ownerEmailVerified need activate: true")
		}
		ownerName := ownerEmail
		if value := input.Get("ownerName"); !isUndefined(value) {
			if ownerName, err = Text(value, "ownerName"); err != nil {
				return nil, err
			}
		}
		// The invitation is the owner's consent to own the organization; skipping it is a platform decision.
		if activate {
			root, err := server.RootPrincipal(ctx, tx, principal)
			if err != nil {
				return nil, err
			}
			if !root {
				return nil, core.NewIamError("ACCESS_DENIED", "Only a root principal can create an active tenant without an owner invitation", 403)
			}
		} else if err := api.requireInvitationDelivery(); err != nil {
			return nil, err
		}
		if !api.allowsChild(parent.Get("type"), kind) {
			return nil, core.NewIamError("INVALID_HIERARCHY", "Child type is not permitted")
		}
		ancestry, err := server.Ancestry(ctx, tx, parent)
		if err != nil {
			return nil, err
		}
		if len(ancestry) >= config.MaxDepth {
			return nil, core.NewIamError("MAX_DEPTH", "Maximum tenant depth reached")
		}
		authorityID, err := authorityIDOf(input.Get("authorityId"))
		if err != nil {
			return nil, err
		}
		parentAuthority, err := server.GrantingAuthority(ctx, tx, principal, jsString(parent.Get("id")), authorityID)
		if err != nil {
			return nil, err
		}
		status := "pending"
		if activate {
			status = "active"
		}
		id := ID()
		realm := core.NewObject(
			"id", id, "tenantId", id, "name", name, "type", kind, "parentId", parent.Get("id"), "status", status,
			"boundary", input.Get("boundary"), "createdAt", float64(server.Wall()),
		)
		// Plan defaults for every new tenant, never looser than its parent's own plan (the stricter value wins per
		// key), so an organization cannot escape its limits through child projects. The root tenant's limits are the
		// platform's own and are not passed on. Root can change them per tenant later.
		var defaults, parentLimits any
		if config.TenantDefaults.Limits != nil {
			defaults = config.TenantDefaults.Limits
		}
		if parent.Get("parentId") != nil {
			parentLimits = parent.Get("limits")
		}
		if limits := stricterLimits(defaults, parentLimits); limits != nil {
			realm.Set("limits", limits)
		}
		if config.TenantDefaults.AuthPolicy != nil {
			realm.Set("authPolicy", config.TenantDefaults.AuthPolicy.Spread())
		}
		if boundary := input.Get("boundary"); truthy(boundary) {
			if err := server.Catalog.Validate(ctx, tx, id, boundary); err != nil {
				return nil, err
			}
		}
		if slug := input.Get("slug"); !isUndefined(slug) {
			alias, err := server.ClaimSlug(ctx, tx, id, slug)
			if err != nil {
				return nil, err
			}
			realm.Set("slug", alias)
		}
		region, err := server.Hosts.RegionForNew(ctx, tx, parent, input.Get("region"))
		if err != nil {
			return nil, err
		}
		if region != "" {
			realm.Set("region", region)
		}
		if _, err := tx.Insert(ctx, "tenants", realm); err != nil {
			return nil, err
		}
		authority, err := tx.Insert(ctx, "grantAuthorities", core.NewObject(
			"id", ID(), "tenantId", id, "identityId", "pending", "parentAuthorityId", parentAuthority.Get("id"),
			"ceiling", All(), "revoked", false,
		))
		if err != nil {
			return nil, err
		}
		if activate {
			owner, err := server.Auth.CreateIdentity(ctx, tx, auth.CreateIdentityInput{
				TenantID: id, Email: ownerEmail, Name: ownerName, Owner: true,
				EmailVerified: input.Get("ownerEmailVerified") == true,
			})
			if err != nil {
				return nil, err
			}
			if err := server.OwnerSetup(ctx, tx, realm, owner, authority); err != nil {
				return nil, err
			}
			if err := server.Events.Audit(ctx, tx, principal, "tenant:activate", id, id, "allow", false,
				core.NewObject("ownerId", owner.Get("id"), "invitation", false)); err != nil {
				return nil, err
			}
			return core.NewObject("tenant", realm, "ownerEmail", ownerEmail, "owner", PublicIdentity(owner)), nil
		}
		inviteToken := Token()
		created := float64(server.Wall())
		invitation, err := tx.Insert(ctx, "ownerInvitations", core.NewObject(
			"id", ID(), "tenantId", id, "email", ownerEmail, "tokenHash", Hash(inviteToken), "uniqueKey", Hash(inviteToken),
			"authorityId", authority.Get("id"), "createdAt", created, "expiresAt", created+config.InvitationLifetimeMs,
			"consumed", false, "creatorId", principal.Identity.Get("id"),
		))
		if err != nil {
			return nil, err
		}
		if err := api.queueOwnerInvitation(ctx, tx, realm, ownerEmail, inviteToken, float64(server.Wall())); err != nil {
			return nil, err
		}
		return core.NewObject("tenant", realm, "invitationId", invitation.Get("id"), "ownerEmail", ownerEmail), nil
	}, false)
	if err != nil {
		return Out[apitypes.TenantsCreateOutput]{}, err
	}
	return Out[apitypes.TenantsCreateOutput]{Value: result}, nil
}

// Get is POST {basePath}/tenants/get. Returns a tenant with its status, parent, alias, policies, limits, and boundary.
func (api *TenantsAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsGetInput]) (Out[apitypes.TenantsGetOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:tenants:read", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		return call.Tenant, nil
	}, false)
	if err != nil {
		return Out[apitypes.TenantsGetOutput]{}, err
	}
	return Out[apitypes.TenantsGetOutput]{Value: result}, nil
}

// ListChildren is POST {basePath}/tenants/listChildren. Lists the direct children of a tenant, whatever their status.
func (api *TenantsAPI) ListChildren(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsListChildrenInput]) (Out[apitypes.TenantsListChildrenOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:tenants:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		children, err := call.Tx.Find(ctx, "tenants", core.NewObject("parentId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		return recordsOf(children), nil
	}, false)
	if err != nil {
		return Out[apitypes.TenantsListChildrenOutput]{}, err
	}
	return Out[apitypes.TenantsListChildrenOutput]{Value: result}, nil
}

// ListInvitations is POST {basePath}/tenants/listInvitations. Lists a tenant's owner invitations without their tokens.
func (api *TenantsAPI) ListInvitations(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsListInvitationsInput]) (Out[apitypes.TenantsListInvitationsOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:tenants:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		invitations, err := call.Tx.Find(ctx, "ownerInvitations", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		result := make([]any, 0, len(invitations))
		for _, invitation := range invitations {
			result = append(result, withoutInvitationSecrets(invitation))
		}
		return result, nil
	}, false)
	if err != nil {
		return Out[apitypes.TenantsListInvitationsOutput]{}, err
	}
	return Out[apitypes.TenantsListInvitationsOutput]{Value: result}, nil
}

// Lookup is POST {basePath}/tenants/lookup (public: no request credential). Resolves a tenant's public alias, or an
// address it signs in at, to its ID, name, and type, so a sign-in page can ask for an organization name instead of a
// tenant ID. In a multi-region deployment an organization homed elsewhere answers WRONG_REGION.
func (api *TenantsAPI) Lookup(ctx context.Context, input In[apitypes.TenantsLookupInput]) (Out[apitypes.TenantsLookupOutput], error) {
	server := api.server
	notFound := func() error { return core.NewIamError("NOT_FOUND", "Organization not found", 404) }
	if rawHost := input.Get("host"); !isUndefined(rawHost) {
		host, err := Text(rawHost, "host", 260)
		if err != nil {
			return Out[apitypes.TenantsLookupOutput]{}, err
		}
		result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
			match, err := server.Hosts.Resolve(ctx, host, tx)
			if err != nil {
				return nil, err
			}
			if match == nil {
				return nil, notFound()
			}
			realm, err := server.Tenant(ctx, tx, match.TenantID)
			if err != nil {
				return nil, err
			}
			if err := server.Hosts.AssertServedHere(ctx, tx, realm, match.HostRegion); err != nil {
				return nil, err
			}
			return api.discovery(ctx, tx, realm)
		})
		if err != nil {
			return Out[apitypes.TenantsLookupOutput]{}, err
		}
		return Out[apitypes.TenantsLookupOutput]{Value: result}, nil
	}
	alias, err := Slug(input.Get("slug"))
	if err != nil {
		return Out[apitypes.TenantsLookupOutput]{}, err
	}
	// found is the discovery; nil with known set when the alias exists but its organization is inactive.
	known := false
	found, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		known = false
		record, err := tx.Get(ctx, "tenantAliases", alias)
		if err != nil {
			return nil, err
		}
		var realm *core.Object
		if record != nil {
			if realm, err = tx.Get(ctx, "tenants", jsString(record.Get("tenantId"))); err != nil {
				return nil, err
			}
		}
		inactive := realm == nil || realm.Get("status") != "active"
		if !inactive {
			ancestry, err := server.Ancestry(ctx, tx, realm)
			if err != nil {
				return nil, err
			}
			inactive = someInactive(ancestry)
		}
		if inactive {
			known = record != nil
			return nil, nil
		}
		if err := server.Hosts.AssertServedHere(ctx, tx, realm, ""); err != nil {
			return nil, err
		}
		return api.discovery(ctx, tx, realm)
	})
	if err != nil {
		return Out[apitypes.TenantsLookupOutput]{}, err
	}
	if found != nil {
		return Out[apitypes.TenantsLookupOutput]{Value: found}, nil
	}
	// An alias this region's database does not know may live in another region (`regions.locate`).
	if !known {
		if elsewhere := server.Hosts.RemoteAlias(ctx, alias); elsewhere != nil {
			return Out[apitypes.TenantsLookupOutput]{}, elsewhere
		}
	}
	return Out[apitypes.TenantsLookupOutput]{}, notFound()
}

// Reparent is POST {basePath}/tenants/reparent. Moves a tenant, with its whole subtree, under a different parent, with
// hierarchy, depth, cycle, and destination-authority checks.
func (api *TenantsAPI) Reparent(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsReparentInput]) (Out[apitypes.TenantsReparentOutput], error) {
	server := api.server
	maxDepth := server.Config.MaxDepth
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:tenants:update", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, target := call.Tx, call.Principal, call.Tenant
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		parentID, err := Text(input.Get("parentId"), "parentId")
		if err != nil {
			return nil, err
		}
		parent, err := server.Tenant(ctx, tx, parentID)
		if err != nil {
			return nil, err
		}
		if target.Get("parentId") == nil || target.Get("status") == "pending" || target.Get("status") == "deleted" {
			return nil, core.NewIamError("INVALID_TRANSITION", "Tenant cannot be moved")
		}
		if parent.Get("id") == target.Get("parentId") {
			return nil, invalidInput("Tenant is already under this parent")
		}
		inactive := parent.Get("status") != "active"
		if !inactive {
			ancestry, err := server.Ancestry(ctx, tx, parent)
			if err != nil {
				return nil, err
			}
			inactive = someInactive(ancestry)
		}
		if inactive {
			return nil, core.NewIamError("TENANT_INACTIVE", "New parent ancestry must be active")
		}
		if !api.allowsChild(parent.Get("type"), target.Get("type")) {
			return nil, core.NewIamError("INVALID_HIERARCHY", "Child type is not permitted under the new parent")
		}
		realms, err := tx.Find(ctx, "tenants", nil, nil)
		if err != nil {
			return nil, err
		}
		targetID := jsString(target.Get("id"))
		subtree := newOrderedSet(targetID)
		frontier := []string{targetID}
		height := 1
		for depth := 0; depth < maxDepth && len(frontier) > 0; depth++ {
			var next []string
			for _, realm := range realms {
				if parentOf := realm.Get("parentId"); truthy(parentOf) && containsString(frontier, jsString(parentOf)) {
					next = append(next, jsString(realm.Get("id")))
				}
			}
			if len(next) > 0 {
				height++
				for _, child := range next {
					subtree.Add(child)
				}
			}
			frontier = next
		}
		if subtree.Has(jsString(parent.Get("id"))) {
			return nil, core.NewIamError("INVALID_HIERARCHY", "Cannot move a tenant under its own subtree")
		}
		ancestry, err := server.Ancestry(ctx, tx, parent)
		if err != nil {
			return nil, err
		}
		if len(ancestry)+height > maxDepth {
			return nil, core.NewIamError("MAX_DEPTH", "Maximum tenant depth reached")
		}
		authorityID, err := authorityIDOf(input.Get("authorityId"))
		if err != nil {
			return nil, err
		}
		if _, err := server.GrantingAuthority(ctx, tx, principal, jsString(parent.Get("id")), authorityID); err != nil {
			return nil, err
		}
		// Security clearances: never out from under the scheme its labels and clearances were written under.
		if err := AssertSchemeKept(ctx, server, tx, target, parent, subtree.Values()); err != nil {
			return nil, err
		}
		updated, err := tx.Put(ctx, "tenants", target.Spread(core.NewObject("parentId", parent.Get("id"))))
		if err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "tenant:reparent", targetID, targetID, "allow", false,
			core.NewObject("from", target.Get("parentId"), "to", parent.Get("id"))); err != nil {
			return nil, err
		}
		return updated, nil
	}, false)
	if err != nil {
		return Out[apitypes.TenantsReparentOutput]{}, err
	}
	return Out[apitypes.TenantsReparentOutput]{Value: result}, nil
}

// ResendInvitation is POST {basePath}/tenants/resendInvitation. Sends an owner invitation again with a new token and a fresh lifetime; the earlier link stops working.
func (api *TenantsAPI) ResendInvitation(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsResendInvitationInput]) (Out[apitypes.TenantsResendInvitationOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:tenants:update", jsString(input.Get("invitationId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, realm := call.Tx, call.Principal, call.Tenant
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		if err := api.requireInvitationDelivery(); err != nil {
			return nil, err
		}
		invitation, err := server.Scoped(ctx, tx, "ownerInvitations", input.Get("invitationId"), jsString(tenantID))
		if err != nil {
			return nil, err
		}
		if truthy(invitation.Get("consumed")) || truthy(invitation.Get("revoked")) {
			return nil, core.NewIamError("CONFLICT", "Invitation is already consumed or revoked", 409)
		}
		inviteToken := Token()
		now := float64(server.Wall())
		renewed, err := tx.Put(ctx, "ownerInvitations", invitation.Spread(core.NewObject(
			"tokenHash", Hash(inviteToken), "uniqueKey", Hash(inviteToken), "createdAt", now,
			"expiresAt", now+server.Config.InvitationLifetimeMs,
		)))
		if err != nil {
			return nil, err
		}
		if err := api.queueOwnerInvitation(ctx, tx, realm, invitation.Get("email"), inviteToken, now); err != nil {
			return nil, err
		}
		return core.NewObject("invitationId", renewed.Get("id"), "email", renewed.Get("email"), "expiresAt", renewed.Get("expiresAt")), nil
	}, false)
	if err != nil {
		return Out[apitypes.TenantsResendInvitationOutput]{}, err
	}
	return Out[apitypes.TenantsResendInvitationOutput]{Value: result}, nil
}

// RevokeInvitation is POST {basePath}/tenants/revokeInvitation. Cancels an owner invitation so its link can no longer be used.
func (api *TenantsAPI) RevokeInvitation(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsRevokeInvitationInput]) (Out[apitypes.TenantsRevokeInvitationOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:tenants:update", jsString(input.Get("invitationId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		if err := server.Auth.RequireRecent(call.Principal.Auth()); err != nil {
			return nil, err
		}
		invitation, err := server.Scoped(ctx, tx, "ownerInvitations", input.Get("invitationId"), jsString(tenantID))
		if err != nil {
			return nil, err
		}
		if truthy(invitation.Get("consumed")) || truthy(invitation.Get("revoked")) {
			return nil, core.NewIamError("CONFLICT", "Invitation is already consumed or revoked", 409)
		}
		revoked, err := tx.Put(ctx, "ownerInvitations", invitation.Spread(core.NewObject("revoked", true)))
		if err != nil {
			return nil, err
		}
		return withoutInvitationSecrets(revoked), nil
	}, false)
	if err != nil {
		return Out[apitypes.TenantsRevokeInvitationOutput]{}, err
	}
	return Out[apitypes.TenantsRevokeInvitationOutput]{Value: result}, nil
}

// RevokeSessions is POST {basePath}/tenants/revokeSessions. Signs everyone out of a tenant at once, keeping your own
// session unless you pass includeSelf; role sessions sourced from the tenant end too, and its remembered devices are
// forgotten (the caller's own are kept unless includeSelf). On the root tenant only root may.
func (api *TenantsAPI) RevokeSessions(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsRevokeSessionsInput]) (Out[apitypes.TenantsRevokeSessionsOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:tenants:update", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, target := call.Tx, call.Principal, call.Tenant
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		if target.Get("parentId") == nil {
			root, err := server.RootPrincipal(ctx, tx, principal)
			if err != nil {
				return nil, err
			}
			if !root {
				return nil, core.NewIamError("ACCESS_DENIED", "Only root administrators can sign everyone out of the root tenant", 403)
			}
		}
		includeSelf := input.Get("includeSelf") == true
		targetID := target.Get("id")
		revoked := 0.0
		sessions, err := tx.Find(ctx, "sessions", nil, nil)
		if err != nil {
			return nil, err
		}
		for _, session := range sessions {
			if (session.Get("tenantId") == targetID || session.Get("sourceTenantId") == targetID) &&
				(includeSelf || session.Get("id") != principal.Session.Get("id")) {
				// endSession also removes the impersonation sessions an administrator opened through this one.
				if err := server.Auth.EndSession(ctx, tx, jsString(session.Get("id"))); err != nil {
					return nil, err
				}
				revoked++
			}
		}
		// Remembered devices are forgotten too, or a stolen password plus device cookie would still skip MFA after
		// "sign everyone out". The caller keeps theirs when they keep their own session.
		devices, err := tx.Find(ctx, "authDevices", core.NewObject("tenantId", targetID), nil)
		if err != nil {
			return nil, err
		}
		for _, device := range devices {
			if includeSelf || device.Get("identityId") != principal.Identity.Get("id") {
				if err := tx.Delete(ctx, "authDevices", jsString(device.Get("id"))); err != nil {
					return nil, err
				}
			}
		}
		if err := server.Events.Audit(ctx, tx, principal, "tenant:revoke-sessions", jsString(targetID), jsString(targetID), "allow", false,
			core.NewObject("revoked", revoked, "includeSelf", includeSelf)); err != nil {
			return nil, err
		}
		return core.NewObject("revoked", revoked), nil
	}, false)
	if err != nil {
		return Out[apitypes.TenantsRevokeSessionsOutput]{}, err
	}
	return Out[apitypes.TenantsRevokeSessionsOutput]{Value: result}, nil
}

// SetAccessPolicy is POST {basePath}/tenants/setAccessPolicy. Sets organization-wide floors for just-in-time
// activation that every eligible binding in the tenant must meet; replaces the whole policy, `null` clears it.
func (api *TenantsAPI) SetAccessPolicy(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsSetAccessPolicyInput]) (Out[apitypes.TenantsSetAccessPolicyOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:tenants:update", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, target := call.Tx, call.Principal, call.Tenant
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		if err := rejectDeleted(target); err != nil {
			return nil, err
		}
		next := target.Spread()
		next.Delete("accessPolicy")
		if value := input.Get("accessPolicy"); value != nil {
			policy, err := TenantAccessPolicy(value)
			if err != nil {
				return nil, err
			}
			if policy.Len() > 0 {
				next.Set("accessPolicy", policy)
			}
		}
		updated, err := tx.Put(ctx, "tenants", next)
		if err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "tenant:access-policy", jsString(target.Get("id")), jsString(target.Get("id")), "allow", false,
			core.NewObject("accessPolicy", coalesce(next.Get("accessPolicy"), nil))); err != nil {
			return nil, err
		}
		return updated, nil
	}, false)
	if err != nil {
		return Out[apitypes.TenantsSetAccessPolicyOutput]{}, err
	}
	return Out[apitypes.TenantsSetAccessPolicyOutput]{Value: result}, nil
}

// SetAuthPolicy is POST {basePath}/tenants/setAuthPolicy. Sets the tenant's authentication policy: MFA, allowed
// sign-in methods, session lifetimes, password rules, network restrictions, and impersonation; `null` clears it. The
// root tenant's policy is set by root administrators only.
func (api *TenantsAPI) SetAuthPolicy(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsSetAuthPolicyInput]) (Out[apitypes.TenantsSetAuthPolicyOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:tenants:update", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, target := call.Tx, call.Principal, call.Tenant
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		if err := rejectDeleted(target); err != nil {
			return nil, err
		}
		// A platform staff member's allowlist or method restriction on the root tenant would lock every root
		// administrator out, and bootstrap recovery signs in there too.
		if target.Get("parentId") == nil {
			root, err := server.RootPrincipal(ctx, tx, principal)
			if err != nil {
				return nil, err
			}
			if !root {
				return nil, core.NewIamError("ACCESS_DENIED", "The root tenant’s authentication policy is set by root administrators", 403)
			}
		}
		next := target.Spread()
		next.Delete("authPolicy")
		if value := input.Get("authPolicy"); value != nil {
			policy, err := TenantAuthPolicy(value)
			if err != nil {
				return nil, err
			}
			next.Set("authPolicy", policy)
		}
		// Like blockNetwork's self-lockout guard: an allowlist that leaves out the address the caller's session was
		// issued from (it would end at once) or the one this request comes from (no way back in, and for the root
		// tenant no parent to undo it) is refused. Only the caller's own organization's allowlist judges them.
		ranges, _ := member(next.Get("authPolicy"), "allowedIpRanges").([]any)
		if len(ranges) > 0 && principal.Session.Get("tenantId") == target.Get("id") {
			current := any(core.Undefined)
			if client := server.Auth.CurrentClient(ctx); client != nil && client.IP != "" {
				current = client.IP
			}
			for _, address := range []any{member(principal.Session.Get("client"), "ip"), current} {
				if isUndefined(address) {
					continue
				}
				allowed := false
				for _, network := range ranges {
					if core.IPMatches(jsString(address), jsString(network)) {
						allowed = true
						break
					}
				}
				if !allowed {
					return nil, invalidInput("allowedIpRanges must include your own address")
				}
			}
		}
		updated, err := tx.Put(ctx, "tenants", next)
		if err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "tenant:auth-policy", jsString(target.Get("id")), jsString(target.Get("id")), "allow", false,
			core.NewObject("authPolicy", coalesce(next.Get("authPolicy"), nil))); err != nil {
			return nil, err
		}
		return updated, nil
	}, false)
	if err != nil {
		return Out[apitypes.TenantsSetAuthPolicyOutput]{}, err
	}
	return Out[apitypes.TenantsSetAuthPolicyOutput]{Value: result}, nil
}

// SetBoundary is POST {basePath}/tenants/setBoundary. Sets a root-controlled permissions boundary on a tenant, capping what anyone in it or in any tenant below it may do.
func (api *TenantsAPI) SetBoundary(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsSetBoundaryInput]) (Out[apitypes.TenantsSetBoundaryOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:boundaries:update", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, target := call.Tx, call.Principal, call.Tenant
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		boundary := input.Get("boundary")
		if err := server.Catalog.Validate(ctx, tx, jsString(target.Get("id")), boundary); err != nil {
			return nil, err
		}
		root, err := server.RootPrincipal(ctx, tx, principal)
		if err != nil {
			return nil, err
		}
		if !root {
			return nil, core.NewIamError("ACCESS_DENIED", "Tenant ceilings are platform controlled", 403)
		}
		return tx.Put(ctx, "tenants", target.Spread(core.NewObject("boundary", boundary)))
	}, false)
	if err != nil {
		return Out[apitypes.TenantsSetBoundaryOutput]{}, err
	}
	return Out[apitypes.TenantsSetBoundaryOutput]{Value: result}, nil
}

// SetLimits is POST {basePath}/tenants/setLimits. Sets the tenant's plan limits, root only: how many people, service
// accounts, groups, roles, policies, registered resources, and webhooks it may hold. `null` clears them. Descendants
// are tightened to the new limits per key; loosening or clearing leaves them as they are.
func (api *TenantsAPI) SetLimits(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsSetLimitsInput]) (Out[apitypes.TenantsSetLimitsOutput], error) {
	server := api.server
	maxDepth := server.Config.MaxDepth
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:tenants:update", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, target := call.Tx, call.Principal, call.Tenant
		if err := rejectDeleted(target); err != nil {
			return nil, err
		}
		next := target.Spread()
		next.Delete("limits")
		var limits *core.Object
		if value := input.Get("limits"); value != nil {
			validated, err := TenantLimits(value)
			if err != nil {
				return nil, err
			}
			limits = validated
			next.Set("limits", limits)
		}
		updated, err := tx.Put(ctx, "tenants", next)
		if err != nil {
			return nil, err
		}
		if limits != nil && target.Get("parentId") != nil {
			realms, err := tx.Find(ctx, "tenants", nil, nil)
			if err != nil {
				return nil, err
			}
			targetID := jsString(target.Get("id"))
			below := descendantsOf(realms, targetID, maxDepth)
			for _, realm := range realms {
				realmID := jsString(realm.Get("id"))
				if realmID == targetID || !below[realmID] {
					continue
				}
				tightened := stricterLimits(realm.Get("limits"), limits)
				if tightened == nil {
					continue
				}
				current := realm.Get("limits")
				if nullish(current) {
					current = core.NewObject()
				}
				before, _, err := core.Stringify(current)
				if err != nil {
					return nil, err
				}
				after, _, err := core.Stringify(tightened)
				if err != nil {
					return nil, err
				}
				if after != before {
					if _, err := tx.Put(ctx, "tenants", realm.Spread(core.NewObject("limits", tightened))); err != nil {
						return nil, err
					}
				}
			}
		}
		var recorded any
		if limits != nil {
			recorded = limits
		}
		if err := server.Events.Audit(ctx, tx, principal, "tenant:limits", jsString(target.Get("id")), jsString(target.Get("id")), "allow", false,
			core.NewObject("limits", recorded)); err != nil {
			return nil, err
		}
		return updated, nil
	}, true)
	if err != nil {
		return Out[apitypes.TenantsSetLimitsOutput]{}, err
	}
	return Out[apitypes.TenantsSetLimitsOutput]{Value: result}, nil
}

// SetRegion is POST {basePath}/tenants/setRegion. Moves a tenant's home region in a multi-region deployment, root
// only, so its sign-in is served by that region from then on; `null` makes it inherit its parent's region again.
func (api *TenantsAPI) SetRegion(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsSetRegionInput]) (Out[apitypes.TenantsSetRegionOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:tenants:update", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, target := call.Tx, call.Principal, call.Tenant
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		if err := rejectDeleted(target); err != nil {
			return nil, err
		}
		from, err := server.Hosts.RegionOf(ctx, tx, target)
		if err != nil {
			return nil, err
		}
		next := target.Spread()
		next.Delete("region")
		if value := input.Get("region"); value != nil {
			region, err := server.Hosts.Region(value)
			if err != nil {
				return nil, err
			}
			next.Set("region", region)
		} else if target.Get("parentId") == nil {
			return nil, invalidInput("The root tenant has no parent to inherit a region from")
		}
		updated, err := tx.Put(ctx, "tenants", next)
		if err != nil {
			return nil, err
		}
		to, err := server.Hosts.RegionOf(ctx, tx, next)
		if err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "tenant:region", jsString(target.Get("id")), jsString(target.Get("id")), "allow", false,
			core.NewObject("from", regionOrNull(from), "to", regionOrNull(to))); err != nil {
			return nil, err
		}
		return updated, nil
	}, true)
	if err != nil {
		return Out[apitypes.TenantsSetRegionOutput]{}, err
	}
	return Out[apitypes.TenantsSetRegionOutput]{Value: result}, nil
}

// SetSlug is POST {basePath}/tenants/setSlug. Sets, changes, or removes the tenant's public sign-in alias.
func (api *TenantsAPI) SetSlug(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsSetSlugInput]) (Out[apitypes.TenantsSetSlugOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:tenants:update", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, target := call.Tx, call.Tenant
		if err := server.Auth.RequireRecent(call.Principal.Auth()); err != nil {
			return nil, err
		}
		if err := rejectDeleted(target); err != nil {
			return nil, err
		}
		if previous := target.Get("slug"); !isUndefined(previous) {
			if err := tx.Delete(ctx, "tenantAliases", jsString(previous)); err != nil {
				return nil, err
			}
		}
		next := target.Spread()
		next.Delete("slug")
		if value := input.Get("slug"); value != nil {
			alias, err := server.ClaimSlug(ctx, tx, jsString(target.Get("id")), value)
			if err != nil {
				return nil, err
			}
			next.Set("slug", alias)
		}
		return tx.Put(ctx, "tenants", next)
	}, false)
	if err != nil {
		return Out[apitypes.TenantsSetSlugOutput]{}, err
	}
	return Out[apitypes.TenantsSetSlugOutput]{Value: result}, nil
}

// SetStatus is POST {basePath}/tenants/setStatus. Suspends, reactivates, or deletes a tenant together with its whole
// subtree; suspension and deletion revoke their sessions, and deletion starts the retention window.
func (api *TenantsAPI) SetStatus(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsSetStatusInput]) (Out[apitypes.TenantsSetStatusOutput], error) {
	server := api.server
	maxDepth := server.Config.MaxDepth
	tenantID := input.Get("tenantId")
	status := input.Get("status")
	action := "iam:tenants:update"
	if status == "deleted" {
		action = "iam:tenants:delete"
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, action, jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, target := call.Tx, call.Principal, call.Tenant
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		if (status != "active" && status != "suspended" && status != "deleted") || target.Get("parentId") == nil ||
			target.Get("status") == "deleted" || (target.Get("status") == "pending" && status != "deleted") {
			return nil, core.NewIamError("INVALID_TRANSITION", "Tenant cannot make this transition")
		}
		if parentID := target.Get("parentId"); status == "active" && truthy(parentID) {
			parent, err := server.Tenant(ctx, tx, parentID)
			if err != nil {
				return nil, err
			}
			ancestry, err := server.Ancestry(ctx, tx, parent)
			if err != nil {
				return nil, err
			}
			if someInactive(ancestry) {
				return nil, core.NewIamError("TENANT_INACTIVE", "Parent must be active")
			}
		}
		// Legal holds (privacy.ts) keep people's data: an organization with an active hold cannot be deleted.
		if status == "deleted" {
			if err := AssertNoTenantLegalHold(ctx, tx, jsString(target.Get("id")), server.Now(), float64(maxDepth)); err != nil {
				return nil, err
			}
		}
		now := float64(server.Wall())
		changes := core.NewObject("status", status)
		if status == "deleted" {
			changes.Set("deletedAt", coalesce(target.Get("deletedAt"), now))
		}
		updated, err := tx.Put(ctx, "tenants", target.Spread(changes))
		if err != nil {
			return nil, err
		}
		if status != "active" {
			realms, err := tx.Find(ctx, "tenants", nil, nil)
			if err != nil {
				return nil, err
			}
			targetID := jsString(target.Get("id"))
			affected := descendantsOf(realms, targetID, maxDepth)
			sessions, err := tx.Find(ctx, "sessions", nil, nil)
			if err != nil {
				return nil, err
			}
			for _, session := range sessions {
				source := session.Get("sourceTenantId")
				if affected[jsString(session.Get("tenantId"))] || (truthy(source) && affected[jsString(source)]) {
					if err := tx.Delete(ctx, "sessions", jsString(session.Get("id"))); err != nil {
						return nil, err
					}
				}
			}
			if status == "deleted" {
				for _, realm := range realms {
					if realmID := jsString(realm.Get("id")); affected[realmID] && realmID != targetID {
						if _, err := tx.Put(ctx, "tenants", realm.Spread(core.NewObject(
							"status", "deleted", "deletedAt", coalesce(realm.Get("deletedAt"), now),
						))); err != nil {
							return nil, err
						}
					}
				}
			}
		}
		return updated, nil
	}, false)
	if err != nil {
		return Out[apitypes.TenantsSetStatusOutput]{}, err
	}
	return Out[apitypes.TenantsSetStatusOutput]{Value: result}, nil
}

// Update is POST {basePath}/tenants/update. Renames a tenant.
func (api *TenantsAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsUpdateInput]) (Out[apitypes.TenantsUpdateOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:tenants:update", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		if err := server.Auth.RequireRecent(call.Principal.Auth()); err != nil {
			return nil, err
		}
		if err := rejectDeleted(call.Tenant); err != nil {
			return nil, err
		}
		name, err := Text(input.Get("name"), "name")
		if err != nil {
			return nil, err
		}
		return call.Tx.Put(ctx, "tenants", call.Tenant.Spread(core.NewObject("name", name)))
	}, false)
	if err != nil {
		return Out[apitypes.TenantsUpdateOutput]{}, err
	}
	return Out[apitypes.TenantsUpdateOutput]{Value: result}, nil
}

// Usage is POST {basePath}/tenants/usage. Returns the tenant's current record counts next to its plan limits, for plan pages and metering.
func (api *TenantsAPI) Usage(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsUsageInput]) (Out[apitypes.TenantsUsageOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:tenants:read", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, target := call.Tx, call.Tenant
		targetID := target.Get("id")
		identities, err := tx.Find(ctx, "identities", core.NewObject("tenantId", targetID), nil)
		if err != nil {
			return nil, err
		}
		sessions, err := tx.Find(ctx, "sessions", core.NewObject("tenantId", targetID, "kind", "user"), nil)
		if err != nil {
			return nil, err
		}
		var people []*core.Object
		services := 0.0
		for _, identity := range identities {
			if identity.Get("status") == "deleted" {
				continue
			}
			switch identity.Get("kind") {
			case "user":
				people = append(people, identity)
			case "service":
				services++
			}
		}
		// MFA adoption: people with an enabled authenticator or at least one passkey.
		withFactor := map[string]bool{}
		factors, err := tx.Find(ctx, "authMfa", core.NewObject("tenantId", targetID), nil)
		if err != nil {
			return nil, err
		}
		for _, record := range factors {
			if truthy(record.Get("enabled")) {
				withFactor[jsString(record.Get("identityId"))] = true
			}
		}
		passkeys, err := tx.Find(ctx, "authPasskeys", core.NewObject("tenantId", targetID), nil)
		if err != nil {
			return nil, err
		}
		for _, key := range passkeys {
			withFactor[jsString(key.Get("identityId"))] = true
		}
		enrolled := 0.0
		for _, identity := range people {
			if withFactor[jsString(identity.Get("id"))] {
				enrolled++
			}
		}
		result := core.NewObject("tenantId", targetID, "identities", float64(len(people)), "mfaEnrolled", enrolled,
			"serviceAccounts", services)
		for _, collection := range []string{"groups", "roles", "policies", "resources", "relationships", "webhooks"} {
			rows, err := tx.Find(ctx, collection, core.NewObject("tenantId", targetID), nil)
			if err != nil {
				return nil, err
			}
			result.Set(collection, float64(len(rows)))
		}
		active := 0.0
		now := float64(server.Now())
		for _, session := range sessions {
			if jsNumber(session.Get("expiresAt")) > now {
				active++
			}
		}
		result.Set("activeSessions", active)
		result.Set("limits", coalesce(target.Get("limits"), core.NewObject()))
		return result, nil
	}, false)
	if err != nil {
		return Out[apitypes.TenantsUsageOutput]{}, err
	}
	return Out[apitypes.TenantsUsageOutput]{Value: result}, nil
}
