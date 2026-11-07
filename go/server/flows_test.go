package server

// Ports of the TypeScript tests that exercise flows.ts: the fail-closed trust readers, linking and switching
// identities (tests/server-security.test.ts "requires user proofs for linking and stores each pair once regardless
// of proof order"), AssumeRole against role-specific source permissions and the current trust ("uses role-specific
// source permissions and current trust for temporary credentials"), and single redemption of owner and member
// invitations (tests/server.test.ts "rolls back duplicate owner redemption" and "invites members into an
// organization with roles applied under the inviter authority"). The flows are called on the flow service, since the
// API groups that front them (links, roles.assume) belong to other units.

import (
	"context"
	"sync"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// flowsSkipOnStub skips a test whose flow reached a stub of another unit.
func flowsSkipOnStub(t *testing.T, err error) {
	t.Helper()
	if message, stubbed := idStubbed(err); stubbed {
		t.Skip("blocked by a stub of another unit: " + message)
	}
}

// secondOrganization adds an active organization "Beta" under the root tenant and returns its ID.
func (f *opsFixture) secondOrganization() string {
	tenantID := "beta-" + ID()
	f.put("tenants", core.NewObject("id", tenantID, "tenantId", tenantID, "name", "Beta", "type", "organization",
		"parentId", f.rootTenantID, "status", "active", "createdAt", float64(f.now())))
	return tenantID
}

// sessionOf issues a fresh user session of an identity in process.
func (f *opsFixture) sessionOf(identity *core.Object) core.CredentialInput {
	f.t.Helper()
	issued, err := core.Transact(f.ctx, f.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return f.iam.Auth.IssueSession(ctx, tx, identity, auth.IssueSessionOptions{})
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return core.CredentialInput{Token: jsString(issued.Get("token"))}
}

func TestFlowsReadStoredTrustsFailClosed(t *testing.T) {
	keys := TrustAllowedTagKeys(core.NewObject("allowedTagKeys", []any{"team", "project"}))
	if keys.Any || len(keys.Keys) != 2 || keys.Keys[0] != "team" || keys.Keys[1] != "project" {
		t.Fatalf("listed keys: %+v", keys)
	}
	if keys := TrustAllowedTagKeys(core.NewObject("allowedTagKeys", []any{"*"})); !keys.Any || len(keys.Keys) != 0 {
		t.Fatalf("wildcard: %+v", keys)
	}
	for _, malformed := range []any{core.Undefined, "*", []any{"team", 1.0}} {
		if keys := TrustAllowedTagKeys(core.NewObject("allowedTagKeys", malformed)); keys.Any || len(keys.Keys) != 0 {
			t.Fatalf("malformed %v admits %+v", malformed, keys)
		}
	}
	// ['*', 'team'] is a list of two literal keys: the wildcard counts only alone.
	if keys := TrustAllowedTagKeys(core.NewObject("allowedTagKeys", []any{"*", "team"})); keys.Any || len(keys.Keys) != 2 {
		t.Fatalf("wildcard with another key: %+v", keys)
	}
	for value, mode := range map[any]string{"optional": "optional", "required": "required", "forbidden": "forbidden", "OPTIONAL": "forbidden", true: "forbidden"} {
		if got := TrustSourceIdentityMode(core.NewObject("sourceIdentityMode", value)); got != mode {
			t.Fatalf("sourceIdentityMode %v read as %v", value, got)
		}
	}
	if TrustSourceIdentityMode(core.NewObject()) != "forbidden" {
		t.Fatal("a missing sourceIdentityMode is not forbidden")
	}
	if !TrustPassesSourceAttributes(core.NewObject()) || !TrustPassesSourceAttributes(core.NewObject("passSourceAttributes", true)) ||
		TrustPassesSourceAttributes(core.NewObject("passSourceAttributes", false)) || TrustPassesSourceAttributes(core.NewObject("passSourceAttributes", "true")) {
		t.Fatal("passSourceAttributes is not read fail-closed")
	}
	if !TrustRequiresMfa(core.NewObject()) || !TrustRequiresMfa(core.NewObject("requireMfa", "false")) || !TrustRequiresMfa(core.NewObject("requireMfa", true)) ||
		TrustRequiresMfa(core.NewObject("requireMfa", false)) {
		t.Fatal("requireMfa is not read fail-closed")
	}
	if !externalIDMatches(nil, core.Undefined) || !externalIDMatches("", "anything") {
		t.Fatal("a trust without an external ID refuses")
	}
	if !externalIDMatches(Hash("external-secret"), "external-secret") || externalIDMatches(Hash("external-secret"), "wrong") ||
		externalIDMatches(Hash("external-secret"), core.Undefined) || externalIDMatches(Hash("external-secret"), 1.0) {
		t.Fatal("external IDs are not compared by hash")
	}
}

func TestFlowsLinkingRequiresUserProofsAndStoresEachPairOnce(t *testing.T) {
	linked := "linked"
	f := newOpsFixture(t, func(options *BetterIamOptions) { options.Onboarding = &OnboardingOptions{Mode: &linked} })
	alice := f.member("alice")
	credential := f.sessionOf(alice)
	betaID := f.secondOrganization()
	other, err := core.Transact(f.ctx, f.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return f.iam.Auth.CreateIdentity(ctx, tx, auth.CreateIdentityInput{TenantID: betaID, Email: "alice@acme.test", Name: "Other tenant user", EmailVerified: true})
	})
	if err != nil {
		t.Fatal(err)
	}
	targetCredential := f.sessionOf(other)
	flows := f.iam.Context.Flows
	link, err := flows.LinkIdentities(f.ctx, credential, targetCredential)
	flowsSkipOnStub(t, err)
	if err != nil {
		t.Fatal(err)
	}
	_, err = flows.LinkIdentities(f.ctx, targetCredential, credential)
	expectCode(t, err, "CONFLICT")
	switched, err := flows.SwitchIdentity(f.ctx, credential, core.NewObject("linkId", link.Get("id"), "targetCredential", core.NewObject("token", targetCredential.Token)))
	if err != nil {
		t.Fatal(err)
	}
	principal := must(f.iam.Authenticate(f.ctx, core.CredentialInput{Token: jsString(switched.Get("token"))}))
	if principal.Identity.Get("tenantId") != betaID {
		t.Fatalf("switched into %v", principal.Identity.Get("tenantId"))
	}
	// Revoking the link (links.revoke marks it revoked) ends switching through it.
	f.put("identityLinks", f.get("identityLinks", jsString(link.Get("id"))).Spread(core.NewObject("revoked", true)))
	_, err = flows.SwitchIdentity(f.ctx, credential, core.NewObject("linkId", link.Get("id"), "targetCredential", core.NewObject("token", targetCredential.Token)))
	expectError(t, err, "INVALID_LINK", "Invalid identity link")
	// Linking again, in the other order, revives the same pair.
	relinked := must(flows.LinkIdentities(f.ctx, targetCredential, credential))
	if relinked.Get("id") != link.Get("id") || relinked.Get("revoked") != false {
		t.Fatalf("relinked: %s (link %v)", core.MustStringify(relinked), link.Get("id"))
	}
	if links := f.find("identityLinks", core.NewObject()); len(links) != 1 {
		t.Fatalf("%d links stored", len(links))
	}
	// A root administrator never links.
	_, err = flows.LinkIdentities(f.ctx, f.rootCredential(), targetCredential)
	expectError(t, err, "INVALID_LINK", "Only separate ordinary tenant identities can link")
	// Nor does an identity link with another of its own tenant.
	_, err = flows.LinkIdentities(f.ctx, credential, f.sessionOf(f.member("bob")))
	expectError(t, err, "INVALID_LINK", "Only separate ordinary tenant identities can link")
	// Linking is off unless onboarding is linked.
	plain := newOpsFixture(t, nil)
	_, err = plain.iam.Context.Flows.LinkIdentities(plain.ctx, plain.owner, plain.owner)
	expectError(t, err, "LINKING_DISABLED", "Account linking disabled")
}

func TestFlowsAssumeRoleUsesRoleSourcePermissionsAndCurrentTrust(t *testing.T) {
	f := newOpsFixture(t, nil)
	alice := f.member("alice")
	credential := f.sessionOf(alice)
	betaID := f.secondOrganization()
	betaAuthority := "authority-" + ID()
	f.put("grantAuthorities", core.NewObject("id", betaAuthority, "tenantId", betaID, "identityId", f.rootID, "ceiling", All(), "revoked", false))
	reader := f.put("roles", core.NewObject("id", "role-"+ID(), "tenantId", betaID, "name", "Reader", "uniqueKey", "name:reader",
		"document", allowDocument("documents:read"), "authorityId", betaAuthority))
	trust := f.put("trusts", core.NewObject("id", "trust-"+ID(), "tenantId", betaID, "sourceTenantId", f.tenantID,
		"sourceIdentityId", alice.Get("id"), "roleId", reader.Get("id"), "requireMfa", false, "externalIdHash", Hash("external-secret"),
		"authorityId", betaAuthority, "revoked", false, "createdAt", float64(f.now())))
	// Alice may assume exactly this role in her own organization.
	assumer := f.put("roles", core.NewObject("id", "role-"+ID(), "tenantId", f.tenantID, "name", "Assumer", "uniqueKey", "name:assumer",
		"document", core.NewObject("version", 1.0, "statements", []any{core.NewObject("effect", "allow", "actions", []any{"iam:roles:assume"},
			"resources", []any{"iam/" + jsString(reader.Get("id"))})}), "authorityId", f.authorityID))
	f.bind("identity", jsString(alice.Get("id")), jsString(assumer.Get("id")))
	flows := f.iam.Context.Flows
	_, err := flows.AssumeRole(f.ctx, credential, core.NewObject("tenantId", betaID, "trustId", trust.Get("id"), "externalId", "wrong"))
	flowsSkipOnStub(t, err)
	expectError(t, err, "ACCESS_DENIED", "Role trust does not permit assumption")
	assumed, err := flows.AssumeRole(f.ctx, credential, core.NewObject("tenantId", betaID, "trustId", trust.Get("id"), "externalId", "external-secret"))
	flowsSkipOnStub(t, err)
	if err != nil {
		t.Fatal(err)
	}
	token := core.CredentialInput{Token: jsString(assumed.Get("token"))}
	decide := func(action string) bool {
		t.Helper()
		decision, err := f.iam.Authorize(f.ctx, AuthorizationRequest{Credential: token, TenantID: betaID, Action: action, Resource: ResourceTarget{Type: "document", ID: "b-doc"}})
		if err != nil {
			t.Fatal(err)
		}
		return decision.Allowed
	}
	if !decide("documents:read") || decide("documents:write") {
		t.Fatal("the role session does not carry exactly the role's permissions")
	}
	// A role session cannot assume a role in turn.
	_, err = flows.AssumeRole(f.ctx, token, core.NewObject("tenantId", betaID, "trustId", trust.Get("id"), "externalId", "external-secret"))
	expectError(t, err, "ROLE_CHAINING_DISABLED", "Role chaining is disabled")
	// Revoking the trust ends its sessions.
	f.put("trusts", f.get("trusts", jsString(trust.Get("id"))).Spread(core.NewObject("revoked", true)))
	_, err = f.iam.Authenticate(f.ctx, token)
	expectCode(t, err, "UNAUTHENTICATED")
}

func TestFlowsRedeemAnOwnerInvitationOnce(t *testing.T) {
	var mu sync.Mutex
	var inbox []auth.DeliveryMessage
	f := newOpsFixture(t, func(options *BetterIamOptions) {
		options.Authentication.SendEmail = func(ctx context.Context, message auth.DeliveryMessage) error {
			mu.Lock()
			defer mu.Unlock()
			inbox = append(inbox, message)
			return nil
		}
	})
	created, err := f.iam.API.Tenants.Create(f.ctx, f.rootCredential(), Input[apitypes.TenantsCreateInput](core.NewObject(
		"parentId", f.rootTenantID, "type", "organization", "name", "Concurrent", "ownerEmail", "concurrent@example.test")))
	flowsSkipOnStub(t, err)
	if err != nil {
		t.Fatal(err)
	}
	tenantID := jsString(member(member(created.Value, "tenant"), "id"))
	if _, err := f.iam.Auth.DispatchOutbox(f.ctx, 0); err != nil {
		t.Fatal(err)
	}
	var token string
	mu.Lock()
	for _, message := range inbox {
		if message.TenantID == tenantID {
			token = message.Payload["token"]
		}
	}
	mu.Unlock()
	if token == "" {
		t.Fatal("no owner invitation was delivered")
	}
	flows := f.iam.Context.Flows
	_, err = flows.AcceptOwnerInvitation(f.ctx, core.NewObject("tenantId", tenantID, "token", "wrong-token", "name", "Owner", "password", "a strong concurrent owner password"))
	expectError(t, err, "INVITATION_INVALID", "Invitation is invalid")
	input := core.NewObject("tenantId", tenantID, "token", token, "name", "Owner", "password", "a strong concurrent owner password")
	results := make([]*core.Object, 2)
	errs := make([]error, 2)
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			results[index], errs[index] = flows.AcceptOwnerInvitation(f.ctx, input)
		}(index)
	}
	wait.Wait()
	fulfilled := 0
	for index := range results {
		flowsSkipOnStub(t, errs[index])
		if errs[index] == nil {
			fulfilled++
			if member(results[index], "token") == nil || member(member(results[index], "identity"), "owner") != true {
				t.Fatalf("enrollment: %s", core.MustStringify(results[index]))
			}
		} else {
			expectError(t, errs[index], "INVITATION_INVALID", "Invitation is invalid")
		}
	}
	if fulfilled != 1 {
		t.Fatalf("%d redemptions succeeded", fulfilled)
	}
	if owners := f.find("identities", core.NewObject("tenantId", tenantID, "owner", true)); len(owners) != 1 {
		t.Fatalf("%d owners", len(owners))
	}
	if f.get("tenants", tenantID).Get("status") != "active" {
		t.Fatal("the tenant was not activated")
	}
	// A link credential needs linked onboarding.
	_, err = flows.AcceptOwnerInvitation(f.ctx, input.Spread(core.NewObject("linkCredential", core.NewObject("token", f.owner.Token))))
	expectError(t, err, "LINKING_DISABLED", "Linked onboarding is disabled")
}

func TestFlowsRedeemAMemberInvitationOnceUnderTheInviterAuthority(t *testing.T) {
	var mu sync.Mutex
	var inbox []auth.DeliveryMessage
	f := newOpsFixture(t, func(options *BetterIamOptions) {
		options.Authentication.SendEmail = func(ctx context.Context, message auth.DeliveryMessage) error {
			mu.Lock()
			defer mu.Unlock()
			inbox = append(inbox, message)
			return nil
		}
	})
	// The root administrator holds the organization's grant authority, so it invites.
	root := f.rootCredential()
	reader := f.role("Reader", "documents:read")
	_, err := f.iam.API.Identities.Invite(f.ctx, root, Input[apitypes.IdentitiesInviteInput](core.NewObject(
		"tenantId", f.tenantID, "email", "new@acme.test", "name", "New person", "roleIds", []any{reader.Get("id")})))
	flowsSkipOnStub(t, err)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.iam.Auth.DispatchOutbox(f.ctx, 0); err != nil {
		t.Fatal(err)
	}
	var token string
	mu.Lock()
	for _, message := range inbox {
		if message.TenantID == f.tenantID && message.Template == "member-invitation" {
			if message.To != "new@acme.test" {
				t.Fatalf("delivered to %s", message.To)
			}
			token = message.Payload["token"]
		}
	}
	mu.Unlock()
	if token == "" {
		t.Fatal("no member invitation was delivered")
	}
	flows := f.iam.Context.Flows
	_, err = flows.AcceptMemberInvitation(f.ctx, core.NewObject("tenantId", f.tenantID, "token", "wrong-token", "password", "a strong invited member password"))
	expectCode(t, err, "INVITATION_INVALID")
	input := core.NewObject("tenantId", f.tenantID, "token", token, "password", "a strong invited member password")
	results := make([]*core.Object, 2)
	errs := make([]error, 2)
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			results[index], errs[index] = flows.AcceptMemberInvitation(f.ctx, input)
		}(index)
	}
	wait.Wait()
	var accepted *core.Object
	for index := range results {
		flowsSkipOnStub(t, errs[index])
		if errs[index] == nil {
			if accepted != nil {
				t.Fatal("both redemptions succeeded")
			}
			accepted = results[index]
		} else {
			expectCode(t, errs[index], "INVITATION_INVALID")
		}
	}
	if accepted == nil {
		t.Fatalf("no redemption succeeded: %v", errs)
	}
	identity := member(accepted, "identity")
	if member(identity, "email") != "new@acme.test" || member(identity, "name") != "New person" || member(identity, "emailVerified") != true || member(identity, "owner") != false {
		t.Fatalf("identity: %s", core.MustStringify(identity))
	}
	decision, err := f.iam.Authorize(f.ctx, AuthorizationRequest{Credential: core.CredentialInput{Token: jsString(member(accepted, "token"))}, TenantID: f.tenantID,
		Action: "documents:read", Resource: ResourceTarget{Type: "document", ID: "welcome"}})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatal("the invited role was not applied")
	}
}
