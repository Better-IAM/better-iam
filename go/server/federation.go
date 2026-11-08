package server

// Port of packages/server/src/federation.ts: the trusted callbacks handed to protocol packages (OAuth, SAML, SCIM);
// never HTTP endpoints. completeAuthentication signs a federated login in (linking, SCIM-trusted linking, or
// enrollment), syncRoleMappings follows a directory group's role mappings, and the protocol host exposes the
// server's checks to the protocol packages.

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// RoleMappingSync is federation.ts RoleMappingSync: one push of a directory group's members and mapped roles.
// Credential is nil for ongoing directory updates, which change membership only.
type RoleMappingSync struct {
	TenantID     string
	ConnectionID string
	GroupID      string
	IdentityIDs  []string
	RoleIDs      []string
	Credential   *core.CredentialInput
}

// Federation is federation.ts createFederation().
type Federation struct {
	server   *ServerContext
	bindings *BindingsAPI
	// ProtocolHost is the protocol packages' host (federation.ts protocolHost).
	ProtocolHost *ProtocolHost
}

// scimProvisioned is federation.ts scimProvisioned: whether a first federated sign-in may link to identity because a
// trusted SCIM connection provisioned it. The connection trusts SCIM (trust: true, or a non-empty list of connection
// IDs), the identity is an ordinary active person (never an owner or root administrator, which SCIM never provisions
// anyway), and a SCIM user of a listed, unrevoked connection of the tenant is backed by it.
func scimProvisioned(ctx context.Context, tx core.IamStore, identity *core.Object, trust any) (bool, error) {
	list, isList := trust.([]any)
	if trust != true && !(isList && len(list) > 0) {
		return false, nil
	}
	if identity.Get("kind") != "user" || identity.Get("status") != "active" || truthy(identity.Get("owner")) ||
		truthy(identity.Get("rootAdmin")) {
		return false, nil
	}
	links, err := tx.Find(ctx, "scimUsers", core.NewObject("tenantId", identity.Get("tenantId"), "identityId", identity.Get("id")), nil)
	if err != nil {
		return false, err
	}
	for _, link := range links {
		connectionID := jsString(link.Get("connectionId"))
		if isList {
			listed := false
			for _, item := range list {
				if item == connectionID {
					listed = true
					break
				}
			}
			if !listed {
				continue
			}
		}
		connection, err := tx.Get(ctx, "scimConnections", connectionID)
		if err != nil {
			return false, err
		}
		if connection != nil && connection.Get("tenantId") == identity.Get("tenantId") && connection.Get("revoked") != true {
			return true, nil
		}
	}
	return false, nil
}

// CompleteAuthentication (federation.ts createFederation().completeAuthentication) signs a federated login in. input
// is a FederatedLogin: tenantId, providerId, issuer, subject, and optionally email, name, emailVerified,
// linkingSessionId, linkingIdentityId, attributes and trustScimProvisioned. The result is the auth service's
// completeAuthentication answer (a session, or an MFA challenge).
func (s *Federation) CompleteAuthentication(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	server := s.server
	service := server.Auth
	if input == nil {
		input = core.NewObject()
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		tenantID := input.Get("tenantId")
		if err := service.AssertTenantActive(ctx, tx, tenantID); err != nil {
			return nil, err
		}
		// Directory-driven attributes: the provider's mapped values replace the stored ones on every sign-in.
		withAttributes := func(record *core.Object) (*core.Object, error) {
			if isUndefined(input.Get("attributes")) {
				return record, nil
			}
			attributes, err := AttributeValues(server.Catalog.IdentityAttributes, input.Get("attributes"))
			if err != nil {
				return nil, err
			}
			return tx.Put(ctx, "identities", record.Spread(core.NewObject("attributes", attributes)))
		}
		complete := func(record *core.Object) (*core.Object, error) {
			identity, err := withAttributes(record)
			if err != nil {
				return nil, err
			}
			return service.CompleteAuthentication(ctx, tx, identity, "federated", "")
		}
		key, _, err := core.Stringify([]any{input.Get("providerId"), input.Get("issuer"), input.Get("subject")})
		if err != nil {
			return nil, err
		}
		link := func(identityID any) error {
			_, err := tx.Insert(ctx, "externalIdentities", core.NewObject(
				"id", ID(), "tenantId", tenantID, "uniqueKey", key, "identityId", identityID,
				"providerId", input.Get("providerId"), "issuer", input.Get("issuer"), "subject", input.Get("subject"),
			))
			return err
		}
		mappings, err := tx.Find(ctx, "externalIdentities", core.NewObject("tenantId", tenantID, "uniqueKey", key), nil)
		if err != nil {
			return nil, err
		}
		var mapping, identity *core.Object
		if len(mappings) > 0 {
			mapping = mappings[0]
			if identity, err = tx.Get(ctx, "identities", jsString(mapping.Get("identityId"))); err != nil {
				return nil, err
			}
		}
		if truthy(input.Get("linkingSessionId")) {
			linkedSession, err := tx.Get(ctx, "sessions", jsString(input.Get("linkingSessionId")))
			if err != nil {
				return nil, err
			}
			var linkedIdentity *core.Object
			if linkedSession != nil {
				if linkedIdentity, err = tx.Get(ctx, "identities", jsString(linkedSession.Get("identityId"))); err != nil {
					return nil, err
				}
			}
			if linkedSession == nil || linkedIdentity == nil ||
				!strictEquals(linkedIdentity.Get("id"), input.Get("linkingIdentityId")) ||
				!strictEquals(linkedIdentity.Get("tenantId"), tenantID) || truthy(linkedIdentity.Get("rootAdmin")) ||
				linkedSession.Get("kind") != "user" {
				return nil, core.NewIamError("INVALID_LINK", "Invalid verified account-linking proof", 403)
			}
			verified, err := server.Principals.CurrentPrincipal(ctx, tx, &Principal{Identity: linkedIdentity, Session: linkedSession})
			if err != nil {
				return nil, err
			}
			if err := service.RequireRecent(verified.Auth()); err != nil {
				return nil, err
			}
			if mapping != nil && (identity == nil || !strictEquals(identity.Get("id"), linkedIdentity.Get("id"))) {
				return nil, core.NewIamError("ACCOUNT_LINK_CONFLICT", "External identity is already linked to another account", 409)
			}
			if mapping == nil {
				if err := link(linkedIdentity.Get("id")); err != nil {
					return nil, err
				}
				if err := server.Events.Audit(ctx, tx, verified, "identity:link-provider", jsString(tenantID),
					jsString(linkedIdentity.Get("id")), "allow", false, nil); err != nil {
					return nil, err
				}
			}
			return complete(linkedIdentity)
		}
		if identity == nil {
			if !truthy(input.Get("email")) || !truthy(input.Get("emailVerified")) {
				return nil, core.NewIamError("VERIFIED_EMAIL_REQUIRED", "Federation enrollment needs a verified email")
			}
			// As with self sign-up, nobody joins the platform (root) tenant by signing in somewhere else: platform
			// accounts are created by an administrator, then linked.
			tenant, err := server.Tenant(ctx, tx, tenantID)
			if err != nil {
				return nil, err
			}
			if tenant.Get("parentId") == nil {
				return nil, core.NewIamError("FORBIDDEN", "Root identity provisioning requires an administrator", 403)
			}
			address, err := Email(input.Get("email"))
			if err != nil {
				return nil, err
			}
			found, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "email", address), nil)
			if err != nil {
				return nil, err
			}
			var existing *core.Object
			if len(found) > 0 {
				existing = found[0]
			}
			// A directory that provisions people through SCIM and signs them in through SSO is one administrator's
			// decision: with `trustScimProvisioned`, the IdP's verified email claims the account SCIM created for it.
			// One link per provider: an account already linked through this connection under another subject is not
			// re-linked (that would be a second IdP account taking it over).
			if existing != nil {
				trusted, err := scimProvisioned(ctx, tx, existing, input.Get("trustScimProvisioned"))
				if err != nil {
					return nil, err
				}
				alreadyLinked := false
				if trusted {
					links, err := tx.Find(ctx, "externalIdentities", core.NewObject("tenantId", tenantID, "identityId", existing.Get("id")), nil)
					if err != nil {
						return nil, err
					}
					for _, other := range links {
						if strictEquals(other.Get("providerId"), input.Get("providerId")) {
							alreadyLinked = true
							break
						}
					}
				}
				if trusted && !alreadyLinked {
					if err := link(existing.Get("id")); err != nil {
						return nil, err
					}
					// The IdP vouched for the address (a trusted domain), which SCIM alone never does.
					linked := existing
					if !truthy(existing.Get("emailVerified")) {
						if linked, err = tx.Put(ctx, "identities", existing.Spread(core.NewObject("emailVerified", true))); err != nil {
							return nil, err
						}
					}
					if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
						"id", ID(), "tenantId", tenantID, "actorId", linked.Get("id"), "action", "identity:link-provider",
						"resourceId", linked.Get("id"), "timestamp", float64(server.Now()), "outcome", "allow",
						"metadata", core.NewObject("providerId", input.Get("providerId"), "via", "scim"),
					)); err != nil {
						return nil, err
					}
					return complete(linked)
				}
				return nil, core.NewIamError("ACCOUNT_LINK_REQUIRED", "Authenticate the existing account before linking this provider", 409)
			}
			name := coalesce(input.Get("name"), input.Get("email"))
			created, err := service.CreateIdentity(ctx, tx, auth.CreateIdentityInput{
				TenantID: tenantID, Email: address, Name: name, EmailVerified: true,
			})
			if err != nil {
				return nil, err
			}
			identity = created
			if err := link(identity.Get("id")); err != nil {
				return nil, err
			}
		}
		return complete(identity)
	})
}

// SyncRoleMappings (federation.ts createFederation().syncRoleMappings): teams that sync their members from the
// directory group follow every push; with an administrator's credential, the group's bindings tagged with the SCIM
// connection are made to match the mapped roles (granted under that administrator's ceiling).
func (s *Federation) SyncRoleMappings(ctx context.Context, tx core.IamStore, input RoleMappingSync) (err error) {
	server := s.server
	// Teams that sync their members from this directory group follow every push (teams.ts).
	if _, err := SyncTeamsFromGroups(ctx, server, tx, input.TenantID, core.NewObject("groupId", input.GroupID, "actorId", "directory-sync")); err != nil {
		return err
	}
	// Ongoing directory updates change membership only. Grant configuration requires an actual administrator
	// credential and retains that administrator's ceiling.
	if input.Credential == nil {
		return nil
	}
	credential := *input.Credential
	if _, err := server.Scoped(ctx, tx, "groups", input.GroupID, input.TenantID); err != nil {
		return err
	}
	existing, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", input.TenantID, "subjectType", "group",
		"subjectId", input.GroupID, "scimConnectionId", input.ConnectionID), nil)
	if err != nil {
		return err
	}
	for _, binding := range existing {
		if roleID, ok := binding.Get("roleId").(string); ok && containsString(input.RoleIDs, roleID) {
			continue
		}
		if _, err := s.bindings.Delete(ctx, credential, Input[apitypes.BindingsDeleteInput](core.NewObject(
			"tenantId", input.TenantID, "bindingId", binding.Get("id"),
		))); err != nil {
			return err
		}
	}
	for _, roleID := range input.RoleIDs {
		bound := false
		for _, binding := range existing {
			if binding.Get("roleId") == roleID {
				bound = true
				break
			}
		}
		if bound {
			continue
		}
		created, err := s.bindings.Create(ctx, credential, Input[apitypes.BindingsCreateInput](core.NewObject(
			"tenantId", input.TenantID, "roleId", roleID, "subjectType", "group", "subjectId", input.GroupID,
		)))
		if err != nil {
			return err
		}
		model, err := ToModel(created.Value)
		if err != nil {
			return err
		}
		binding, ok := model.(*core.Object)
		if !ok {
			return core.NewIamError("INTERNAL_ERROR", "bindings.create returned no binding", 500)
		}
		if _, err := tx.Put(ctx, "bindings", binding.Spread(core.NewObject("scimConnectionId", input.ConnectionID))); err != nil {
			return err
		}
	}
	return nil
}

// CreateFederation builds the Federation (federation.ts createFederation): the federation callbacks and the
// protocol host handed to protocol packages.
func CreateFederation(server *ServerContext, bindings *BindingsAPI) *Federation {
	federation := &Federation{server: server, bindings: bindings}
	federation.ProtocolHost = &ProtocolHost{federation: federation, Store: server.Store}
	return federation
}

// ProtocolHost is federation.ts protocolHost: the trusted callbacks protocol packages (OAuth, SAML, SCIM) call.
type ProtocolHost struct {
	federation *Federation
	// Store is the deployment's store.
	Store core.IamStore
}

// Authenticate resolves a credential to its principal.
func (h *ProtocolHost) Authenticate(ctx context.Context, input core.CredentialInput) (*Principal, error) {
	return h.federation.server.Principals.Authenticate(ctx, input)
}

// ValidateIdentityAttributes validates identity attributes a protocol (SCIM) maps from its payload against
// `permissions.identityAttributes`.
func (h *ProtocolHost) ValidateIdentityAttributes(value any) (*core.Object, error) {
	return AttributeValues(h.federation.server.Catalog.IdentityAttributes, value)
}

// ValidateSession validates a session by its ID.
func (h *ProtocolHost) ValidateSession(ctx context.Context, sessionID any) (*auth.Principal, error) {
	return h.federation.server.Auth.ValidateSessionID(ctx, sessionID)
}

// Authorize requires access to a resource (the operation's checks, without a mutation).
func (h *ProtocolHost) Authorize(ctx context.Context, credential core.CredentialInput, action string, resource core.ResourceRef) error {
	return h.federation.server.Operations.RequireAccess(ctx, AuthorizationRequest{
		Credential: credential, TenantID: resource.TenantID, Action: action,
		Resource: ResourceTarget{Type: resource.Type, ID: resource.ID},
	})
}

// CompleteAuthentication is Federation.CompleteAuthentication.
func (h *ProtocolHost) CompleteAuthentication(ctx context.Context, input *core.Object) (*core.Object, error) {
	return h.federation.CompleteAuthentication(ctx, input)
}

// SyncRoleMappings is Federation.SyncRoleMappings.
func (h *ProtocolHost) SyncRoleMappings(ctx context.Context, tx core.IamStore, input RoleMappingSync) error {
	return h.federation.SyncRoleMappings(ctx, tx, input)
}

// IdentityStatusChanged runs after SCIM deactivated or reactivated a person (in its transaction): their license
// seats follow at once, as after an administrator's `identities.setStatus` (licenses.ts).
func (h *ProtocolHost) IdentityStatusChanged(ctx context.Context, tx core.IamStore, tenantID, connectionID, identityID string) error {
	_, err := ReconcileIdentityLicenses(ctx, h.federation.server, tx, tenantID, []string{identityID}, "directory-sync")
	return err
}

// GroupDeleted runs before SCIM deletes a group's record (in its transaction): the group's license assignments go
// with it and the seats they carried are released, as `groups.delete` does (licenses.ts).
func (h *ProtocolHost) GroupDeleted(ctx context.Context, tx core.IamStore, tenantID, connectionID, groupID string) error {
	_, err := ReleaseGroupLicenses(ctx, h.federation.server, tx, tenantID, groupID, "directory-sync")
	return err
}

// RecordAudit records a protocol's audit event and fans it out (webhooks, plugins, `iam.events` subscribers).
func (h *ProtocolHost) RecordAudit(ctx context.Context, tx core.IamStore, event *core.Object) error {
	return h.federation.server.Events.RecordAudit(ctx, tx, event)
}

// LiveGrants are the groups and roles an identity holds right now, as decisions see them: live memberships, and
// bindings that have started, not ended, are inside their access window, and (when eligible) activated. For claims
// protocols put in tokens (the OAuth provider's `iam` scope), so a token never lists a role that grants nothing yet.
// The result is `{ groupIds, roleIds }`.
func (h *ProtocolHost) LiveGrants(ctx context.Context, identityID, tenantID string) (*core.Object, error) {
	server := h.federation.server
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		sources, err := server.Decisions.GrantSources(ctx, tx, identityID, tenantID)
		if err != nil {
			return nil, err
		}
		roles := newOrderedSet()
		for _, binding := range sources.Bindings {
			roles.Add(jsString(binding.Get("roleId")))
		}
		return core.NewObject("groupIds", stringsOf(append([]string{}, sources.GroupIDs...)), "roleIds", stringsOf(roles.Values())), nil
	})
}

// ClientAllowed is whether a person may get tokens for an OAuth client: false when an app of the catalog governs the
// client and the person does not have it (applications.ts). The OAuth provider asks on every code, token refresh and
// userinfo.
func (h *ProtocolHost) ClientAllowed(ctx context.Context, identityID, tenantID, clientID string) (bool, error) {
	return AppClientAllowed(ctx, h.federation.server, identityID, tenantID, clientID)
}

// AssertTrustChange runs before a tenant-managed sign-in connection trusts something new (an IdP issuer, a signing
// certificate): whoever controls that trust can sign in as every account linked through it (providerID). So the
// change needs a recent sign-in in person, and when owners or root administrators are linked through it, a caller
// who could control those accounts anyway: a root principal, or for owners another owner of the tenant (as
// `assertAccountControl` requires for their sign-in address). Refusals are 403 ACCESS_DENIED.
func (h *ProtocolHost) AssertTrustChange(ctx context.Context, credential core.CredentialInput, tenantID, providerID string) error {
	server := h.federation.server
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return err
	}
	return server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return err
		}
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return err
		}
		root, err := server.RootPrincipal(ctx, tx, principal)
		if err != nil {
			return err
		}
		owner := principal.Session.Get("kind") == "user" && truthy(principal.Identity.Get("owner")) &&
			principal.Identity.Get("tenantId") == tenantID && principal.Session.Get("tenantId") == tenantID
		links, err := tx.Find(ctx, "externalIdentities", core.NewObject("tenantId", tenantID, "providerId", providerID), nil)
		if err != nil {
			return err
		}
		for _, link := range links {
			linked, err := tx.Get(ctx, "identities", jsString(link.Get("identityId")))
			if err != nil {
				return err
			}
			if linked == nil || (!truthy(linked.Get("owner")) && !truthy(linked.Get("rootAdmin"))) || root {
				continue
			}
			if !truthy(linked.Get("rootAdmin")) && owner {
				continue
			}
			message := "An owner signs in through this connection; only an owner can change what it trusts"
			if truthy(linked.Get("rootAdmin")) {
				message = "A root administrator signs in through this connection; only a root administrator can change what it trusts"
			}
			return core.NewIamError("ACCESS_DENIED", message, 403)
		}
		return nil
	})
}
