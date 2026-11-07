package server

// Port of packages/server/src/flows.ts: multi-step flows that create sessions or cross tenant boundaries and
// therefore do not fit the single-tenant operation envelope (invitation acceptance, identity linking and switching,
// AssumeRole), and the fail-closed readers of stored trusts.

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// externalIDMatches is whether a presented external ID matches a trust's stored hash: SHA-256 hex digests compared
// in constant time (with a length check first). A trust without an external ID matches anything.
func externalIDMatches(expectedHash any, provided any) bool {
	if !truthy(expectedHash) {
		return true
	}
	text, ok := provided.(string)
	if !ok {
		return false
	}
	expected := utf8Bytes(jsString(expectedHash))
	actual := utf8Bytes(Hash(text))
	return len(expected) == len(actual) && subtle.ConstantTimeCompare(expected, actual) == 1
}

// roleSource is whether a session may source a role session: one acting in its own right, or a session token minted
// from one.
func roleSource(session *core.Object) bool {
	return ActsInOwnRight(session) || session.Get("kind") == "session-token"
}

// TrustTagKeys is what TrustAllowedTagKeys reads from a trust.
type TrustTagKeys struct {
	Any  bool
	Keys []string
}

// TrustAllowedTagKeys (flows.ts trustAllowedTagKeys): the session tag keys a stored trust admits, read fail-closed:
// a list of strings, where the `*` wildcard counts only as exactly ['*']. Anything malformed (not an array, or
// holding a non-string) admits no tags; legacy trusts without the field admit none either.
func TrustAllowedTagKeys(trust *core.Object) TrustTagKeys {
	list, ok := trust.Get("allowedTagKeys").([]any)
	if !ok {
		return TrustTagKeys{Keys: []string{}}
	}
	keys := make([]string, len(list))
	for index, item := range list {
		key, ok := item.(string)
		if !ok {
			return TrustTagKeys{Keys: []string{}}
		}
		keys[index] = key
	}
	if len(keys) == 1 && keys[0] == "*" {
		return TrustTagKeys{Any: true, Keys: []string{}}
	}
	return TrustTagKeys{Keys: keys}
}

// TrustSourceIdentityMode (flows.ts trustSourceIdentityMode): a stored trust's source-identity mode, read
// fail-closed: any value but the three literals means 'forbidden'.
func TrustSourceIdentityMode(trust *core.Object) SourceIdentityMode {
	switch value := trust.Get("sourceIdentityMode"); value {
	case "optional", "required":
		return value.(string)
	}
	return "forbidden"
}

// TrustPassesSourceAttributes (flows.ts trustPassesSourceAttributes): whether a stored trust passes the source
// identity's attributes into its role sessions: legacy trusts without the field pass them, and a malformed
// (non-boolean) value fails closed and passes nothing.
func TrustPassesSourceAttributes(trust *core.Object) bool {
	value := trust.Get("passSourceAttributes")
	if flag, ok := value.(bool); ok {
		return flag
	}
	return isUndefined(value)
}

// TrustRequiresMfa (flows.ts trustRequiresMfa): whether a stored trust requires MFA of the source session, read
// fail-closed: only the boolean false waives it.
func TrustRequiresMfa(trust *core.Object) bool {
	return trust.Get("requireMfa") != false
}

// flowAuthorityID is an optional authority ID as GrantingAuthority takes it ("" for none).
func flowAuthorityID(value any) string {
	text, _ := value.(string)
	return text
}

// flowStrings are the strings of a stored string list.
func flowStrings(value any) []string {
	list, _ := value.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		out = append(out, jsString(item))
	}
	return out
}

// AssertMemberInvitationGrantable (flows.ts assertMemberInvitationGrantable): A member invitation grants no more
// than its inviter could bind directly, now as when it was sent: the inviter must still be active and still hold
// iam:identities:create, iam:bindings:create on each role and iam:groups:update on each group (and
// iam:licenses:assign when a license product is assigned to one of the groups, then or since), and the authorities
// behind the invitation and each group's bindings must still be theirs. Demoting or disabling the inviter ends the
// invitations they sent. Throws INVITATION_INVALID otherwise. Acceptance checks it, and so does
// `identities.resendInvitation`, so only an invitation that can still be accepted goes out again.
func AssertMemberInvitationGrantable(ctx context.Context, server *ServerContext, tx core.IamStore, invitation *core.Object, tenantID string) error {
	refused := func(message ...string) error {
		text := "The inviter can no longer grant this access"
		if len(message) > 0 {
			text = message[0]
		}
		return core.NewIamError("INVITATION_INVALID", text)
	}
	authorityID := invitation.Get("authorityId")
	if !isUndefined(authorityID) {
		_, ok, err := server.AuthorityChain(ctx, tx, flowAuthorityID(authorityID))
		if err != nil {
			return err
		}
		if !ok {
			return refused("Invitation authority revoked")
		}
	}
	inviter, err := tx.Get(ctx, "identities", jsString(invitation.Get("inviterId")))
	if err != nil {
		return err
	}
	if inviter == nil || inviter.Get("status") != "active" || server.IdentityExpired(inviter) {
		return refused("The inviter can no longer invite")
	}
	asInviter := server.Decisions.SimulatedPrincipal(inviter, true)
	inviterMay := func(action, resourceID string) (bool, error) {
		decision, err := server.Decisions.Decide(ctx, tx, asInviter, AuthorizationRequest{
			TenantID: tenantID, Action: action, Resource: ResourceTarget{Type: "iam", ID: resourceID},
		}, true)
		return decision.Allowed, err
	}
	inviterHolds := func(authorityID any) bool {
		_, err := server.GrantingAuthority(ctx, tx, asInviter, tenantID, flowAuthorityID(authorityID))
		return err == nil
	}
	allowed, err := inviterMay("iam:identities:create", tenantID)
	if err != nil {
		return err
	}
	if !allowed || (!isUndefined(authorityID) && !inviterHolds(authorityID)) {
		return refused()
	}
	for _, roleID := range flowStrings(invitation.Get("roleIds")) {
		allowed, err := inviterMay("iam:bindings:create", roleID)
		if err != nil {
			return err
		}
		if !allowed {
			return refused()
		}
	}
	for _, groupID := range flowStrings(invitation.Get("groupIds")) {
		allowed, err := inviterMay("iam:groups:update", groupID)
		if err != nil {
			return err
		}
		if !allowed {
			return refused()
		}
		bindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "group", "subjectId", groupID), nil)
		if err != nil {
			return err
		}
		for _, binding := range bindings {
			if !inviterHolds(binding.Get("authorityId")) {
				return refused()
			}
		}
	}
	// Groups that carry license seats (then or since) need the inviter's iam:licenses:assign (api/groups.ts).
	if err := AssertMayClaimLicenses(ctx, server, tx, asInviter, tenantID, invitation.Get("groupIds"), ""); err != nil {
		var denied *OperationDenied
		if !errors.As(err, &denied) {
			return err
		}
		return refused()
	}
	return nil
}

// FlowService is flows.ts FlowService.
type FlowService struct {
	server *ServerContext
}

// CreateFlows builds the FlowService (flows.ts createFlows).
func CreateFlows(server *ServerContext) *FlowService {
	return &FlowService{server: server}
}

// byIdentityID orders identities by id (`a.id < b.id ? -1 : a.id > b.id ? 1 : 0`).
func byIdentityID(a, b *core.Object) int {
	return compareUTF16(jsString(a.Get("id")), jsString(b.Get("id")))
}

// flowCredential is a credential carried inside an input object (`{ token }` or `{ headers }`).
func flowCredential(value any) core.CredentialInput {
	var credential core.CredentialInput
	record, ok := value.(*core.Object)
	if !ok || record == nil {
		return credential
	}
	if token, ok := record.Get("token").(string); ok {
		credential.Token = token
	}
	if headers, ok := record.Get("headers").(*core.Object); ok && headers != nil {
		credential.Headers = http.Header{}
		headers.Entries(func(key string, value any) bool {
			switch typed := value.(type) {
			case string:
				credential.Headers.Add(key, typed)
			case []any:
				for _, item := range typed {
					credential.Headers.Add(key, jsString(item))
				}
			default:
				if !nullish(value) {
					credential.Headers.Add(key, jsString(value))
				}
			}
			return true
		})
	}
	return credential
}

// flowScoped is ctx.scoped with a tenant ID taken from input as it is (a record only matches a string tenant ID).
func flowScoped(ctx context.Context, tx core.IamStore, collection string, recordID any, tenantID any) (*core.Object, error) {
	id, err := Text(recordID, "id")
	if err != nil {
		return nil, err
	}
	record, err := tx.Get(ctx, collection, id)
	if err != nil {
		return nil, err
	}
	if record == nil || record.Get("tenantId") != tenantID {
		return nil, core.NewIamError("NOT_FOUND", "Resource not found", 404)
	}
	return record, nil
}

// numberPointer is a numeric member as a *float64 (nil when it is not a number).
func numberPointer(value any) *float64 {
	if number, ok := value.(float64); ok {
		return &number
	}
	return nil
}

// enrollment is `{ identity: publicIdentity(identity), ...issued }`.
func enrollment(identity, issued *core.Object) *core.Object {
	return core.NewObject("identity", PublicIdentity(identity)).Assign(issued)
}

// insertIdentityLink links two identities (sorted by id) in the first one's tenant.
func insertIdentityLink(ctx context.Context, tx core.IamStore, pair []*core.Object) (*core.Object, error) {
	return tx.Insert(ctx, "identityLinks", core.NewObject(
		"id", ID(), "tenantId", pair[0].Get("tenantId"),
		"uniqueKey", jsString(pair[0].Get("id"))+":"+jsString(pair[1].Get("id")),
		"leftId", pair[0].Get("id"), "rightId", pair[1].Get("id"), "revoked", false,
	))
}

// AcceptOwnerInvitation (flows.ts FlowService.acceptOwnerInvitation): Public: redeems an owner invitation, activates
// the pending tenant, and signs the owner in. Input: tenantId, token, name, password, and optionally linkCredential
// (the organization creator's ordinary user session, linked to the new owner when linked onboarding is on).
func (s *FlowService) AcceptOwnerInvitation(ctx context.Context, input *core.Object) (*core.Object, error) {
	server := s.server
	authService := server.Auth
	var linkPrincipal *Principal
	if linkCredential := member(input, "linkCredential"); truthy(linkCredential) {
		principal, err := server.Principals.Authenticate(ctx, flowCredential(linkCredential))
		if err != nil {
			return nil, err
		}
		linkPrincipal = principal
	}
	if linkPrincipal != nil {
		if !server.Config.LinkedOnboarding {
			return nil, core.NewIamError("LINKING_DISABLED", "Linked onboarding is disabled")
		}
		if err := authService.RequireRecent(linkPrincipal.Auth()); err != nil {
			return nil, err
		}
		if truthy(linkPrincipal.Identity.Get("rootAdmin")) {
			return nil, core.NewIamError("PROTECTED_IDENTITY", "Root identities cannot link")
		}
		if linkPrincipal.Session.Get("kind") != "user" || linkPrincipal.Identity.Get("kind") != "user" {
			return nil, core.NewIamError("INVALID_LINK", "Linked onboarding requires an ordinary user session")
		}
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		realm, err := server.Tenant(ctx, tx, member(input, "tenantId"))
		if err != nil {
			return nil, err
		}
		if realm.Get("status") != "pending" {
			return nil, core.NewIamError("INVITATION_INVALID", "Invitation is invalid")
		}
		token, err := Text(member(input, "token"), "token")
		if err != nil {
			return nil, err
		}
		found, err := tx.Find(ctx, "ownerInvitations", core.NewObject("tenantId", realm.Get("id"), "tokenHash", Hash(token)), nil)
		if err != nil {
			return nil, err
		}
		var invitation *core.Object
		if len(found) > 0 {
			invitation = found[0]
		}
		if invitation == nil || truthy(invitation.Get("consumed")) || truthy(invitation.Get("revoked")) || jsNumber(invitation.Get("expiresAt")) <= float64(server.Wall()) {
			return nil, core.NewIamError("INVITATION_INVALID", "Invitation is invalid")
		}
		if parentID := realm.Get("parentId"); truthy(parentID) {
			parent, err := server.Tenant(ctx, tx, parentID)
			if err != nil {
				return nil, err
			}
			ancestry, err := server.Ancestry(ctx, tx, parent)
			if err != nil {
				return nil, err
			}
			for _, item := range ancestry {
				if item.Get("status") != "active" {
					return nil, core.NewIamError("TENANT_INACTIVE", "Parent inactive")
				}
			}
		}
		realmID := jsString(realm.Get("id"))
		authority, err := server.Scoped(ctx, tx, "grantAuthorities", invitation.Get("authorityId"), realmID)
		if err != nil {
			return nil, err
		}
		if _, ok, err := server.AuthorityChain(ctx, tx, jsString(authority.Get("id"))); err != nil {
			return nil, err
		} else if !ok {
			return nil, core.NewIamError("INVITATION_INVALID", "Invitation authority revoked")
		}
		name, err := Text(member(input, "name"), "name")
		if err != nil {
			return nil, err
		}
		identity, err := authService.CreateIdentity(ctx, tx, auth.CreateIdentityInput{
			TenantID: realmID, Email: invitation.Get("email"), Name: name, Password: member(input, "password"),
			HasPassword: !isUndefined(member(input, "password")), Owner: true, EmailVerified: true,
		})
		if err != nil {
			return nil, err
		}
		if err := server.OwnerSetup(ctx, tx, realm, identity, authority); err != nil {
			return nil, err
		}
		if _, err := tx.Put(ctx, "tenants", realm.Spread(core.NewObject("status", "active"))); err != nil {
			return nil, err
		}
		if _, err := tx.Put(ctx, "ownerInvitations", invitation.Spread(core.NewObject("consumed", true))); err != nil {
			return nil, err
		}
		// The owner just set a password: the session is a password sign-in, recorded as one and refused like one where
		// the organization does not accept passwords.
		issued, err := authService.CompleteAuthentication(ctx, tx, identity, "password", "")
		if err != nil {
			return nil, err
		}
		if linkPrincipal != nil {
			current, err := server.Principals.CurrentPrincipal(ctx, tx, linkPrincipal)
			if err != nil {
				return nil, err
			}
			if invitation.Get("creatorId") != current.Identity.Get("id") || truthy(current.Identity.Get("rootAdmin")) || current.Session.Get("kind") != "user" {
				return nil, core.NewIamError("ACCESS_DENIED", "Only this ordinary user organization creator may link during enrollment", 403)
			}
			pair := []*core.Object{current.Identity, identity}
			sortStable(pair, byIdentityID)
			if _, err := insertIdentityLink(ctx, tx, pair); err != nil {
				return nil, err
			}
		}
		if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
			"id", ID(), "tenantId", realmID, "actorId", identity.Get("id"), "action", "tenant:activate",
			"resourceId", realmID, "timestamp", server.Wall(), "outcome", "allow",
		)); err != nil {
			return nil, err
		}
		return enrollment(identity, issued), nil
	})
}

// AcceptMemberInvitation (flows.ts FlowService.acceptMemberInvitation): Public: redeems a member invitation, applies
// its bindings under the inviter's authority, and signs the member in. Input: tenantId, token, name (optional when
// the invitation names the member), password.
func (s *FlowService) AcceptMemberInvitation(ctx context.Context, input *core.Object) (*core.Object, error) {
	server := s.server
	authService := server.Auth
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		realm, err := server.Tenant(ctx, tx, member(input, "tenantId"))
		if err != nil {
			return nil, err
		}
		realmID := jsString(realm.Get("id"))
		if err := authService.AssertTenantActive(ctx, tx, realmID); err != nil {
			return nil, err
		}
		token, err := Text(member(input, "token"), "token")
		if err != nil {
			return nil, err
		}
		found, err := tx.Find(ctx, "memberInvitations", core.NewObject("tenantId", realmID, "tokenHash", Hash(token)), nil)
		if err != nil {
			return nil, err
		}
		var invitation *core.Object
		if len(found) > 0 {
			invitation = found[0]
		}
		if invitation == nil || truthy(invitation.Get("consumed")) || truthy(invitation.Get("revoked")) || jsNumber(invitation.Get("expiresAt")) <= float64(server.Wall()) {
			return nil, core.NewIamError("INVITATION_INVALID", "Invitation is invalid")
		}
		// The inviter must still be able to grant what the invitation grants.
		if err := AssertMemberInvitationGrantable(ctx, server, tx, invitation, realmID); err != nil {
			return nil, err
		}
		name := invitation.Get("name")
		if raw := member(input, "name"); !isUndefined(raw) {
			text, err := Text(raw, "name")
			if err != nil {
				return nil, err
			}
			name = text
		}
		if !truthy(name) {
			return nil, invalidInput("A name is required")
		}
		identity, err := authService.CreateIdentity(ctx, tx, auth.CreateIdentityInput{
			TenantID: realmID, Email: invitation.Get("email"), Name: name, Password: member(input, "password"),
			HasPassword: !isUndefined(member(input, "password")), EmailVerified: true,
		})
		if err != nil {
			return nil, err
		}
		identityID := jsString(identity.Get("id"))
		authorityID := invitation.Get("authorityId")
		for _, roleID := range flowStrings(invitation.Get("roleIds")) {
			role, err := server.Scoped(ctx, tx, "roles", roleID, realmID)
			if err != nil {
				return nil, err
			}
			if truthy(role.Get("protected")) {
				return nil, core.NewIamError("PROTECTED_RESOURCE", "Invitation grants a protected role", 403)
			}
			if _, err := tx.Insert(ctx, "bindings", core.NewObject(
				"id", ID(), "tenantId", realmID,
				"uniqueKey", "identity:"+identityID+":"+jsString(role.Get("id"))+":"+jsString(authorityID),
				"subjectType", "identity", "subjectId", identityID, "roleId", role.Get("id"), "authorityId", authorityID,
			)); err != nil {
				return nil, err
			}
		}
		groupIDs := flowStrings(invitation.Get("groupIds"))
		for _, groupID := range groupIDs {
			if _, err := server.Scoped(ctx, tx, "groups", groupID, realmID); err != nil {
				return nil, err
			}
			if _, err := tx.Insert(ctx, "groupMembers", core.NewObject(
				"id", ID(), "tenantId", realmID, "uniqueKey", groupID+":"+identityID, "groupId", groupID, "identityId", identityID,
			)); err != nil {
				return nil, err
			}
		}
		// License products assigned to those groups seat the new member at once (licenses.ts).
		if len(groupIDs) > 0 {
			if _, err := ReconcileGroupLicenses(ctx, server, tx, realmID, invitation.Get("groupIds"), invitation.Get("inviterId")); err != nil {
				return nil, err
			}
		}
		if err := SodAssertIdentity(ctx, server, tx, realmID, identityID); err != nil {
			return nil, err
		}
		if _, err := tx.Put(ctx, "memberInvitations", invitation.Spread(core.NewObject("consumed", true))); err != nil {
			return nil, err
		}
		if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
			"id", ID(), "tenantId", realmID, "actorId", identityID, "action", "identity:invitation:accept",
			"resourceId", invitation.Get("id"), "timestamp", server.Wall(), "outcome", "allow",
			"metadata", core.NewObject(
				"inviterId", invitation.Get("inviterId"), "roleIds", invitation.Get("roleIds"), "groupIds", invitation.Get("groupIds"),
			),
		)); err != nil {
			return nil, err
		}
		// A password sign-in, like the owner invitation's: METHOD_NOT_ALLOWED applies and `session.method` is set.
		issued, err := authService.CompleteAuthentication(ctx, tx, identity, "password", "")
		if err != nil {
			return nil, err
		}
		return enrollment(identity, issued), nil
	})
}

// LinkIdentities (flows.ts FlowService.linkIdentities): links two ordinary user identities of different tenants,
// each proven by a recent session of its own.
func (s *FlowService) LinkIdentities(ctx context.Context, leftCredential core.CredentialInput, rightCredential core.CredentialInput) (*core.Object, error) {
	server := s.server
	if !server.Config.LinkedOnboarding {
		return nil, core.NewIamError("LINKING_DISABLED", "Account linking disabled")
	}
	left, err := server.Principals.Authenticate(ctx, leftCredential)
	if err != nil {
		return nil, err
	}
	right, err := server.Principals.Authenticate(ctx, rightCredential)
	if err != nil {
		return nil, err
	}
	if err := server.Auth.RequireRecent(left.Auth()); err != nil {
		return nil, err
	}
	if err := server.Auth.RequireRecent(right.Auth()); err != nil {
		return nil, err
	}
	if truthy(left.Identity.Get("rootAdmin")) || truthy(right.Identity.Get("rootAdmin")) || left.Session.Get("kind") != "user" ||
		right.Session.Get("kind") != "user" || left.Identity.Get("tenantId") == right.Identity.Get("tenantId") {
		return nil, core.NewIamError("INVALID_LINK", "Only separate ordinary tenant identities can link")
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		currentLeft, err := server.Principals.CurrentPrincipal(ctx, tx, left)
		if err != nil {
			return nil, err
		}
		currentRight, err := server.Principals.CurrentPrincipal(ctx, tx, right)
		if err != nil {
			return nil, err
		}
		if truthy(currentLeft.Identity.Get("rootAdmin")) || truthy(currentRight.Identity.Get("rootAdmin")) ||
			currentLeft.Session.Get("kind") != "user" || currentRight.Session.Get("kind") != "user" {
			return nil, core.NewIamError("INVALID_LINK", "Only ordinary user identities can link")
		}
		identities := []*core.Object{currentLeft.Identity, currentRight.Identity}
		sortStable(identities, byIdentityID)
		tenantID := identities[0].Get("tenantId")
		uniqueKey := jsString(identities[0].Get("id")) + ":" + jsString(identities[1].Get("id"))
		found, err := tx.Find(ctx, "identityLinks", core.NewObject("tenantId", tenantID, "uniqueKey", uniqueKey), nil)
		if err != nil {
			return nil, err
		}
		var existing *core.Object
		if len(found) > 0 {
			existing = found[0]
		}
		if existing != nil && !truthy(existing.Get("revoked")) {
			return nil, core.NewIamError("CONFLICT", "These identities are already linked", 409)
		}
		var link *core.Object
		if existing != nil {
			link, err = tx.Put(ctx, "identityLinks", existing.Spread(core.NewObject("revoked", false)))
		} else {
			link, err = insertIdentityLink(ctx, tx, identities)
		}
		if err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, currentLeft, "identity:link", jsString(currentLeft.Identity.Get("tenantId")), jsString(link.Get("id")), "allow", false, nil); err != nil {
			return nil, err
		}
		return link, nil
	})
}

// SwitchIdentity (flows.ts FlowService.switchIdentity): issues a session of a linked identity, proven by a recent
// session of that identity (`targetCredential`), through the link `linkId`.
func (s *FlowService) SwitchIdentity(ctx context.Context, credential core.CredentialInput, input *core.Object) (*core.Object, error) {
	server := s.server
	source, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return nil, err
	}
	target, err := server.Principals.Authenticate(ctx, flowCredential(member(input, "targetCredential")))
	if err != nil {
		return nil, err
	}
	if err := server.Auth.RequireRecent(target.Auth()); err != nil {
		return nil, err
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		currentSource, err := server.Principals.CurrentPrincipal(ctx, tx, source)
		if err != nil {
			return nil, err
		}
		currentTarget, err := server.Principals.CurrentPrincipal(ctx, tx, target)
		if err != nil {
			return nil, err
		}
		linkID, err := Text(member(input, "linkId"), "linkId")
		if err != nil {
			return nil, err
		}
		link, err := tx.Get(ctx, "identityLinks", linkID)
		if err != nil {
			return nil, err
		}
		var members []any
		if link != nil {
			members = []any{link.Get("leftId"), link.Get("rightId")}
		}
		includes := func(value any) bool {
			for _, item := range members {
				if item == value {
					return true
				}
			}
			return false
		}
		valid := link != nil && !truthy(link.Get("revoked")) && source.Identity.Get("id") != target.Identity.Get("id") &&
			includes(source.Identity.Get("id")) && includes(target.Identity.Get("id")) &&
			!truthy(currentSource.Identity.Get("rootAdmin")) && !truthy(currentTarget.Identity.Get("rootAdmin")) &&
			currentSource.Session.Get("kind") == "user" && currentTarget.Session.Get("kind") == "user"
		if !valid {
			return nil, core.NewIamError("INVALID_LINK", "Invalid identity link", 403)
		}
		session := currentTarget.Session
		method, _ := session.Get("method").(string)
		issued, err := server.Auth.IssueSession(ctx, tx, currentTarget.Identity, auth.IssueSessionOptions{
			Mfa: session.Get("mfa") == true, AuthenticatedAt: numberPointer(session.Get("authenticatedAt")), Method: method,
			// principal.mfaTime carries the target's own ceremony forward, never the switch time.
			MfaAuthenticatedAt: numberPointer(session.Get("mfaAuthenticatedAt")),
		})
		if err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, currentSource, "identity:switch", jsString(currentTarget.Identity.Get("tenantId")), jsString(currentTarget.Identity.Get("id")), "allow", false, nil); err != nil {
			return nil, err
		}
		return issued, nil
	})
}

// AssumeRole (flows.ts FlowService.assumeRole): AssumeRole: exchanges a user session (not impersonated), API key or
// session token for a role session of the trust's tenant, with an optional session name, source identity, tags,
// scope-down policy and JWT format. Role sessions cannot assume roles (ROLE_CHAINING_DISABLED). Audited as
// `iam:roles:assume` in the source tenant and `role:assumed` in the target tenant. The issuing client is recorded on
// the session; a `{ headers }` credential with no client scope set gets the client derived from those headers, as
// `sts.getSessionToken` does.
func (s *FlowService) AssumeRole(ctx context.Context, credential core.CredentialInput, input *core.Object) (*core.Object, error) {
	server := s.server
	// In-process integrations that pass the incoming request's headers as the credential (with no client scope set)
	// get the client derived from those headers (`http.clientInfo`), as `sts.getSessionToken` does, so the role
	// session records its issuing client and allowlists, network blocks and `bindSessionsToIp` judge it.
	if server.Auth.CurrentClient(ctx) == nil && credential.Headers != nil {
		ctx = server.Auth.WithClient(ctx, ClientFromHeaders(server.Options, credential.Headers, server.Config.BaseURL.Href))
	}
	return s.assume(ctx, credential, input)
}

func (s *FlowService) assume(ctx context.Context, credential core.CredentialInput, input *core.Object) (*core.Object, error) {
	server := s.server
	authService := server.Auth
	principalBefore, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return nil, err
	}
	if principalBefore.Session.Get("kind") == "role" {
		return nil, core.NewIamError("ROLE_CHAINING_DISABLED", "Role chaining is disabled")
	}
	if truthy(principalBefore.Session.Get("impersonatorId")) {
		return nil, core.NewIamError("IMPERSONATION_RESTRICTED", "Roles cannot be assumed while impersonating a member", 403)
	}
	// Only the sources a role session may be validated against (principals.ts roleSourceKinds): a delegated agent
	// session is bounded by its delegation and must not mint a role credential (a JWT would outlive it offline).
	if !roleSource(principalBefore.Session) {
		return nil, core.NewIamError("CREDENTIAL_CHAINING_DISABLED", "Delegated sessions cannot assume roles", 400)
	}
	// Input shapes are refused before any lookup; trust-dependent rules run inside the operation.
	sessionName, err := SessionNameValue(member(input, "sessionName"))
	if err != nil {
		return nil, err
	}
	sourceIdentity, err := SourceIdentityValue(member(input, "sourceIdentity"))
	if err != nil {
		return nil, err
	}
	tags, err := SessionTagsValue(member(input, "tags"))
	if err != nil {
		return nil, err
	}
	format, err := CredentialFormat(member(input, "format"))
	if err != nil {
		return nil, err
	}
	audience, err := AudienceValue(member(input, "audience"), format)
	if err != nil {
		return nil, err
	}
	if format == "jwt" && server.SessionTokens == nil {
		return nil, core.NewIamError("FEATURE_DISABLED", "Session JWTs are not enabled on this deployment (sts.jwt)", 403)
	}
	externalID := member(input, "externalId")
	if !isUndefined(externalID) {
		if _, ok := externalID.(string); !ok {
			return nil, invalidInput("externalId must be a string")
		}
	}
	tenantID := member(input, "tenantId")
	requestedTrust, err := flowScoped(ctx, server.Store, "trusts", member(input, "trustId"), tenantID)
	if err != nil {
		return nil, err
	}
	policy := member(input, "policy")
	return Operate(ctx, server.Operations, credential, principalBefore.Identity.Get("tenantId"), "iam:roles:assume", jsString(requestedTrust.Get("roleId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		trust, err := flowScoped(ctx, tx, "trusts", member(input, "trustId"), tenantID)
		if err != nil {
			return nil, err
		}
		targetTenantID := jsString(tenantID)
		if truthy(policy) {
			if err := server.Catalog.Validate(ctx, tx, targetTenantID, policy); err != nil {
				return nil, err
			}
		}
		// Tags and a source identity can satisfy ABAC conditions, so both are closed unless the trust opens them.
		// Stored values are read fail-closed: a malformed list admits no tags, an unknown mode forbids.
		allowedTagKeys := TrustAllowedTagKeys(trust)
		tagKeys := tags.Keys()
		if tagKeys == nil {
			tagKeys = []string{}
		}
		sortStable(tagKeys, compareUTF16)
		tagsAdmitted := allowedTagKeys.Any
		if !tagsAdmitted {
			tagsAdmitted = true
			for _, key := range tagKeys {
				if !containsString(allowedTagKeys.Keys, key) {
					tagsAdmitted = false
					break
				}
			}
		}
		sourceIdentityMode := TrustSourceIdentityMode(trust)
		permitted := roleSource(principal.Session) &&
			!truthy(trust.Get("revoked")) &&
			coalesce(trust.Get("kind"), "identity") == "identity" &&
			trust.Get("sourceIdentityId") == principal.Identity.Get("id") &&
			trust.Get("sourceTenantId") == principal.Identity.Get("tenantId") &&
			!(TrustRequiresMfa(trust) && principal.Session.Get("mfa") != true) &&
			externalIDMatches(trust.Get("externalIdHash"), externalID) &&
			tagsAdmitted &&
			!(sourceIdentityMode == "forbidden" && sourceIdentity != "") &&
			!(sourceIdentityMode == "required" && sourceIdentity == "")
		if !permitted {
			return nil, core.NewIamError("ACCESS_DENIED", "Role trust does not permit assumption", 403)
		}
		targetTenant, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		ancestry, err := server.Ancestry(ctx, tx, targetTenant)
		if err != nil {
			return nil, err
		}
		for _, item := range ancestry {
			if item.Get("status") != "active" {
				return nil, core.NewIamError("TENANT_INACTIVE", "Target tenant inactive")
			}
		}
		role, err := server.Scoped(ctx, tx, "roles", trust.Get("roleId"), targetTenantID)
		if err != nil {
			return nil, err
		}
		bounds, err := RoleDurationBounds(server, trust, format)
		if err != nil {
			return nil, err
		}
		durationSeconds, err := DurationWithin(member(input, "durationSeconds"), bounds)
		if err != nil {
			return nil, err
		}
		// The injected clock, like user sessions, so validation and issuance agree under a test clock.
		now := server.Now()
		identityID := jsString(principal.Identity.Get("id"))
		paths, err := server.Decisions.IdentityGrants(ctx, tx, identityID, jsString(principal.Identity.Get("tenantId")), nil, nil)
		if err != nil {
			return nil, err
		}
		sourceAuthorityIDs := make([]string, len(paths))
		for index, path := range paths {
			sourceAuthorityIDs[index] = path.AuthorityID
		}
		expiresAt := float64(now) + durationSeconds*1000
		if sessionExpiry := jsNumber(principal.Session.Get("expiresAt")); sessionExpiry < expiresAt || sessionExpiry != sessionExpiry {
			expiresAt = sessionExpiry
		}
		draft := core.NewObject(
			"id", ID(), "tenantId", tenantID, "identityId", principal.Identity.Get("id"),
			"originalIdentityId", principal.Identity.Get("id"), "sourceTenantId", principal.Identity.Get("tenantId"),
			"sourceSessionId", principal.Session.Get("id"), "sourceAuthorityIds", stringsOf(sourceAuthorityIDs),
			"roleId", role.Get("id"), "trustId", trust.Get("id"), "kind", "role", "tokenHash", "",
			"createdAt", now, "lastSeenAt", now,
			// The source's authentication carries over; its sign-in method and remembered device do not.
			"authenticatedAt", principal.Session.Get("authenticatedAt"),
			"expiresAt", expiresAt, "mfa", principal.Session.Get("mfa"),
		)
		if mfaAt, ok := principal.Session.Get("mfaAuthenticatedAt").(float64); ok && truthy(principal.Session.Get("mfa")) {
			draft.Set("mfaAuthenticatedAt", mfaAt)
		}
		if truthy(policy) {
			draft.Set("policy", policy)
		}
		if sessionName != "" {
			draft.Set("sessionName", sessionName)
		}
		if sourceIdentity != "" {
			draft.Set("sourceIdentity", sourceIdentity)
		}
		if tags != nil {
			draft.Set("sessionTags", tags)
		}
		// The issuing address, so the target tenant's allowlist and network blocks judge it on every use.
		if client := authService.CurrentClient(ctx); client != nil && (client.IP != "" || client.UserAgent != "" || client.Label != "") {
			draft.Set("client", core.Normalize(*client))
		}
		var audienceValue any = core.Undefined
		if audience != nil {
			audienceValue = stringsOf(audience)
		}
		minted, err := MintCredential(ctx, server, tx, core.NewObject(
			"identity", principal.Identity, "draft", draft, "format", format, "audience", audienceValue,
		))
		if err != nil {
			return nil, err
		}
		session, _ := minted.Get("session").(*core.Object)
		token, _ := minted.Get("token").(string)
		// The target tenant sees who assumed its role, under the new session's context.
		if err := server.Events.Audit(ctx, tx, &Principal{Identity: principal.Identity, Session: session}, "role:assumed", targetTenantID, jsString(role.Get("id")), "allow", false, core.NewObject(
			"trustId", trust.Get("id"), "sourceTenantId", principal.Identity.Get("tenantId"),
			"sourceSessionKind", principal.Session.Get("kind"), "durationSeconds", durationSeconds, "format", format,
			"tagKeys", stringsOf(tagKeys),
			// Whether the source identity's attributes reach this session's decisions (read as a boolean).
			"passSourceAttributes", TrustPassesSourceAttributes(trust),
		)); err != nil {
			return nil, err
		}
		return TemporaryCredential(token, session, now)
	}, false)
}
