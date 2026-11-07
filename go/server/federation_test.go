package server

// Ports of the federation tests: tests/federation-import-gaps.test.ts ("first SSO sign-in of SCIM-provisioned
// people"), tests/security-federation.test.ts (claims about grants, federated enrollment, who may change what a
// connection trusts), and the linking-proof rules of federation.ts completeAuthentication. The SCIM connection and the
// SCIM-provisioned person are seeded as the records @better-iam/scim writes; the SAML connection's trust change is
// asked of the protocol host directly, as the SAML package asks it.

import (
	"context"
	"testing"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// federationHost is the organization fixture's protocol host.
func federationHost(f *appsOrg) *ProtocolHost {
	return f.iam.ProtocolHost.(*ProtocolHost)
}

// federated is what an IdP-backed sign-in hands the server (the SAML/OAuth packages call this with verified claims).
func federated(f *appsOrg, subject, email string, members ...any) (*core.Object, error) {
	input := core.NewObject("tenantId", f.tenantID, "providerId", "acme-okta", "issuer", "https://acme.okta.test",
		"subject", subject, "email", email, "emailVerified", true)
	for index := 0; index+1 < len(members); index += 2 {
		input.Set(members[index].(string), members[index+1])
	}
	return federationHost(f).CompleteAuthentication(f.ctx, input)
}

// scimDirectory seeds a SCIM connection of the organization and a person it provisioned (an unverified address).
func scimDirectory(f *appsOrg, email string) (connection, identity *core.Object) {
	connection = f.insert("scimConnections", core.NewObject("id", ID(), "tenantId", f.tenantID, "name", "Directory",
		"revoked", false, "createdAt", float64(f.now())))
	identity = scimUser(f, connection, email)
	return connection, identity
}

func scimUser(f *appsOrg, connection *core.Object, email string) *core.Object {
	var identity *core.Object
	f.tx(func(ctx context.Context, tx core.IamStore) (err error) {
		identity, err = f.iam.Auth.CreateIdentity(ctx, tx, auth.CreateIdentityInput{TenantID: f.tenantID, Email: email, Name: email})
		if err != nil {
			return err
		}
		_, err = tx.Insert(ctx, "scimUsers", core.NewObject("id", ID(), "tenantId", f.tenantID, "connectionId", connection.Get("id"),
			"identityId", identity.Get("id"), "userName", email, "active", true))
		return err
	})
	return identity
}

func TestFederationLinksSCIMAccountsOnlyWhenTheConnectionTrustsThatSCIMConnection(t *testing.T) {
	f := newAppsOrg(t, nil)
	connection, identity := scimDirectory(f, "ada@acme.test")
	if identity.Get("emailVerified") != false {
		t.Fatalf("a SCIM account starts verified: %v", identity)
	}
	// Without trust, or with an unverified email, or trusting another SCIM connection: no link.
	_, err := federated(f, "okta-ada", "ada@acme.test")
	appsCode(t, err, "ACCOUNT_LINK_REQUIRED")
	_, err = federated(f, "okta-ada", "ada@acme.test", "emailVerified", false, "trustScimProvisioned", true)
	expectError(t, err, "VERIFIED_EMAIL_REQUIRED", "Federation enrollment needs a verified email")
	_, err = federated(f, "okta-ada", "ada@acme.test", "trustScimProvisioned", []any{"another-connection"})
	appsCode(t, err, "ACCOUNT_LINK_REQUIRED")
	_, err = federated(f, "okta-ada", "ada@acme.test", "trustScimProvisioned", []any{})
	appsCode(t, err, "ACCOUNT_LINK_REQUIRED")
	// A federated-only tenant: the trusted connection signs Ada in to the provisioned account and links it.
	f.tx(func(ctx context.Context, tx core.IamStore) error {
		tenant, err := tx.Get(ctx, "tenants", f.tenantID)
		if err != nil {
			return err
		}
		_, err = tx.Put(ctx, "tenants", tenant.Spread(core.NewObject("authPolicy", core.NewObject("allowedMethods", []any{"federated"}))))
		return err
	})
	first, err := federated(f, "okta-ada", "ADA@acme.test", "trustScimProvisioned", []any{connection.Get("id")})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := first.Get("token").(string); !ok || member(first.Get("session"), "identityId") != identity.Get("id") {
		t.Fatalf("first sign-in: %v", first)
	}
	if linked := f.get("identities", jsString(identity.Get("id"))); linked.Get("emailVerified") != true {
		t.Fatalf("linked: %v", linked)
	}
	links := f.find("externalIdentities", core.NewObject("identityId", identity.Get("id")))
	if len(links) != 1 || links[0].Get("providerId") != "acme-okta" || links[0].Get("subject") != "okta-ada" ||
		links[0].Get("uniqueKey") != `["acme-okta","https://acme.okta.test","okta-ada"]` {
		t.Fatalf("links: %v", links)
	}
	var audited *core.Object
	for _, event := range f.find("audit", core.NewObject("tenantId", f.tenantID)) {
		if event.Get("action") == "identity:link-provider" && event.Get("resourceId") == identity.Get("id") {
			audited = event
		}
	}
	if audited == nil {
		t.Fatal("the link is not audited")
	}
	expectJSONValue(t, audited.Get("metadata"), `{"providerId":"acme-okta","via":"scim"}`)
	// Later sign-ins use the link, whatever the connection's setting.
	again, err := federated(f, "okta-ada", "ada@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	if member(again.Get("session"), "identityId") != identity.Get("id") {
		t.Fatalf("again: %v", again)
	}
	// Another account at the same IdP claiming the address does not take the linked account over.
	_, err = federated(f, "okta-mallory", "ada@acme.test", "trustScimProvisioned", true)
	appsCode(t, err, "ACCOUNT_LINK_REQUIRED")
}

func TestFederationNeverLinksAccountsSCIMDidNotProvisionNorThroughARevokedConnection(t *testing.T) {
	f := newAppsOrg(t, nil)
	connection := f.insert("scimConnections", core.NewObject("id", ID(), "tenantId", f.tenantID, "name", "Directory", "revoked", false))
	f.memberIdentity("bob")
	_, err := federated(f, "okta-bob", "bob@acme.test", "trustScimProvisioned", true)
	appsCode(t, err, "ACCOUNT_LINK_REQUIRED")
	// The owner's account is never a target, even if an IdP vouches for its address.
	_, err = federated(f, "okta-owner", "owner@acme.test", "trustScimProvisioned", true)
	appsCode(t, err, "ACCOUNT_LINK_REQUIRED")
	scimUser(f, connection, "cyd@acme.test")
	f.tx(func(ctx context.Context, tx core.IamStore) error {
		_, err := tx.Put(ctx, "scimConnections", connection.Spread(core.NewObject("revoked", true)))
		return err
	})
	_, err = federated(f, "okta-cyd", "cyd@acme.test", "trustScimProvisioned", true)
	appsCode(t, err, "ACCOUNT_LINK_REQUIRED")
}

func TestFederationNeverCreatesPlatformAccountsFromASignInElsewhere(t *testing.T) {
	f := newAppsOrg(t, nil)
	host := federationHost(f)
	_, err := host.CompleteAuthentication(f.ctx, core.NewObject("tenantId", f.rootTenantID, "providerId", "google",
		"issuer", "https://accounts.google.com", "subject", "stranger-1", "email", "stranger@gmail.example", "emailVerified", true))
	expectError(t, err, "FORBIDDEN", "Root identity provisioning requires an administrator")
	// Organizations still enroll verified addresses as documented.
	enrolled, err := host.CompleteAuthentication(f.ctx, core.NewObject("tenantId", f.tenantID, "providerId", "google",
		"issuer", "https://accounts.google.com", "subject", "new-member-1", "email", "New.Member@acme.test", "emailVerified", true))
	if err != nil {
		t.Fatal(err)
	}
	identityID := jsString(member(enrolled.Get("session"), "identityId"))
	identity := f.get("identities", identityID)
	if identity.Get("email") != "new.member@acme.test" || identity.Get("name") != "New.Member@acme.test" || identity.Get("emailVerified") != true {
		t.Fatalf("enrolled: %v", identity)
	}
	if links := f.find("externalIdentities", core.NewObject("tenantId", f.tenantID, "identityId", identityID)); len(links) != 1 {
		t.Fatalf("links: %v", links)
	}
	// Enrollment needs a verified address; a suspended tenant signs nobody in.
	_, err = host.CompleteAuthentication(f.ctx, core.NewObject("tenantId", f.tenantID, "providerId", "google",
		"issuer", "https://accounts.google.com", "subject", "new-member-2", "email", "other@acme.test"))
	appsCode(t, err, "VERIFIED_EMAIL_REQUIRED")
	f.tx(func(ctx context.Context, tx core.IamStore) error {
		tenant, err := tx.Get(ctx, "tenants", f.tenantID)
		if err != nil {
			return err
		}
		_, err = tx.Put(ctx, "tenants", tenant.Spread(core.NewObject("status", "suspended")))
		return err
	})
	_, err = host.CompleteAuthentication(f.ctx, core.NewObject("tenantId", f.tenantID, "providerId", "google",
		"issuer", "https://accounts.google.com", "subject", "new-member-1", "email", "new.member@acme.test", "emailVerified", true))
	if err == nil {
		t.Fatal("a suspended tenant signed someone in")
	}
}

func TestFederationLinksOnlyWithAVerifiedRecentProof(t *testing.T) {
	f := newAppsOrg(t, nil)
	host := federationHost(f)
	alice := f.memberIdentity("alice")
	bob := f.memberIdentity("bob")
	principal, err := f.iam.Auth.Authenticate(f.ctx, f.token("alice"))
	if err != nil {
		t.Fatal(err)
	}
	sessionID := principal.Session.Get("id")
	link := func(subject string, identityID any) (*core.Object, error) {
		return host.CompleteAuthentication(f.ctx, core.NewObject("tenantId", f.tenantID, "providerId", "github",
			"issuer", "https://github.com", "subject", subject, "linkingSessionId", sessionID, "linkingIdentityId", identityID))
	}
	// The proof must be the session's own person.
	_, err = link("gh-alice", bob.Get("id"))
	expectError(t, err, "INVALID_LINK", "Invalid verified account-linking proof")
	_, err = host.CompleteAuthentication(f.ctx, core.NewObject("tenantId", f.tenantID, "providerId", "github",
		"issuer", "https://github.com", "subject", "gh-alice", "linkingSessionId", "no-such-session", "linkingIdentityId", alice.Get("id")))
	appsCode(t, err, "INVALID_LINK")
	linked, err := link("gh-alice", alice.Get("id"))
	if err != nil {
		t.Fatal(err)
	}
	if member(linked.Get("session"), "identityId") != alice.Get("id") {
		t.Fatalf("linked: %v", linked)
	}
	events := 0
	for _, event := range f.find("audit", core.NewObject("tenantId", f.tenantID)) {
		if event.Get("action") == "identity:link-provider" && event.Get("resourceId") == alice.Get("id") && event.Get("actorId") == alice.Get("id") {
			events++
		}
	}
	if events != 1 {
		t.Fatalf("link events: %d", events)
	}
	// Linking again is idempotent (no second link, no second event); later sign-ins use the link.
	if _, err := link("gh-alice", alice.Get("id")); err != nil {
		t.Fatal(err)
	}
	if links := f.find("externalIdentities", core.NewObject("tenantId", f.tenantID, "identityId", alice.Get("id"))); len(links) != 1 {
		t.Fatalf("links: %v", links)
	}
	signedIn, err := host.CompleteAuthentication(f.ctx, core.NewObject("tenantId", f.tenantID, "providerId", "github",
		"issuer", "https://github.com", "subject", "gh-alice"))
	if err != nil || member(signedIn.Get("session"), "identityId") != alice.Get("id") {
		t.Fatalf("sign-in through the link: %v %v", signedIn, err)
	}
	// An external identity linked to someone else is not moved.
	f.insert("externalIdentities", core.NewObject("id", ID(), "tenantId", f.tenantID,
		"uniqueKey", `["github","https://github.com","gh-bob"]`, "identityId", bob.Get("id"), "providerId", "github",
		"issuer", "https://github.com", "subject", "gh-bob"))
	_, err = link("gh-bob", alice.Get("id"))
	expectError(t, err, "ACCOUNT_LINK_CONFLICT", "External identity is already linked to another account")
	// The proof must be recent.
	f.advance(10 * 60_000)
	_, err = link("gh-alice-2", alice.Get("id"))
	appsCode(t, err, "RECENT_AUTH_REQUIRED")
}

func TestFederationLiveGrantsListOnlyRolesInForce(t *testing.T) {
	f := newAppsOrg(t, nil)
	alice := f.memberIdentity("alice")
	role := func(name string) *core.Object {
		policy := f.insert("policies", core.NewObject("id", ID(), "tenantId", f.tenantID, "name", name,
			"document", obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["iam:groups:read"],"resources":["*"]}]}`),
			"version", 1.0, "authorityId", f.ownerAuthorityID))
		return f.insert("roles", core.NewObject("id", ID(), "tenantId", f.tenantID, "name", name,
			"policyIds", []any{policy.Get("id")}, "authorityId", f.ownerAuthorityID))
	}
	deployer := role("Deployer")
	later := role("Starts later")
	f.insert("bindings", core.NewObject("id", ID(), "tenantId", f.tenantID, "subjectType", "identity", "subjectId", alice.Get("id"),
		"roleId", deployer.Get("id"), "authorityId", f.ownerAuthorityID, "eligible", true))
	f.insert("bindings", core.NewObject("id", ID(), "tenantId", f.tenantID, "subjectType", "identity", "subjectId", alice.Get("id"),
		"roleId", later.Get("id"), "authorityId", f.ownerAuthorityID, "startsAt", float64(f.now()+appsDay)))
	host := federationHost(f)
	expectJSONValue(t, must(host.LiveGrants(f.ctx, jsString(alice.Get("id")), f.tenantID)), `{"groupIds":[],"roleIds":[]}`)
	// Live grants: a started binding (twice, listed once) and a live membership.
	f.insert("bindings", core.NewObject("id", ID(), "tenantId", f.tenantID, "subjectType", "identity", "subjectId", alice.Get("id"),
		"roleId", deployer.Get("id"), "authorityId", f.ownerAuthorityID))
	engineering := f.group("Engineering")
	f.addMember(engineering.Get("id"), alice.Get("id"))
	f.insert("bindings", core.NewObject("id", ID(), "tenantId", f.tenantID, "subjectType", "group", "subjectId", engineering.Get("id"),
		"roleId", deployer.Get("id"), "authorityId", f.ownerAuthorityID))
	expectJSONValue(t, must(host.LiveGrants(f.ctx, jsString(alice.Get("id")), f.tenantID)),
		`{"groupIds":["`+jsString(engineering.Get("id"))+`"],"roleIds":["`+jsString(deployer.Get("id"))+`"]}`)
}

func TestFederationLetsOnlyAnOwnerRecentlySignedInChangeWhatAnOwnersConnectionTrusts(t *testing.T) {
	f := newAppsOrg(t, nil)
	host := federationHost(f)
	providerID := "saml:acme"
	// Nobody privileged signs in through it yet: any recent caller passes.
	dana := f.memberIdentity("dana")
	danaSession := f.token("dana")
	if err := host.AssertTrustChange(f.ctx, danaSession, f.tenantID, providerID); err != nil {
		t.Fatal(err)
	}
	f.insert("externalIdentities", core.NewObject("id", ID(), "tenantId", f.tenantID,
		"uniqueKey", `["saml:acme","https://idp.test","owner-at-idp"]`, "identityId", f.ownerID, "providerId", providerID,
		"issuer", "https://idp.test", "subject", "owner-at-idp"))
	err := host.AssertTrustChange(f.ctx, danaSession, f.tenantID, providerID)
	if known := iamError(t, err); known.Code != "ACCESS_DENIED" || known.Status != 403 ||
		known.Message != "An owner signs in through this connection; only an owner can change what it trusts" {
		t.Fatalf("delegated administrator: %v", known)
	}
	if err := host.AssertTrustChange(f.ctx, f.ownerSignIn(), f.tenantID, providerID); err != nil {
		t.Fatal(err)
	}
	// The owner may, but only with a recent sign-in.
	f.advance(10 * 60_000)
	err = host.AssertTrustChange(f.ctx, f.owner, f.tenantID, providerID)
	appsCode(t, err, "RECENT_AUTH_REQUIRED")
	// A root administrator linked through it: only a root principal.
	f.tx(func(ctx context.Context, tx core.IamStore) error {
		_, err := tx.Put(ctx, "identities", dana.Spread(core.NewObject("rootAdmin", true)))
		return err
	})
	f.insert("externalIdentities", core.NewObject("id", ID(), "tenantId", f.tenantID,
		"uniqueKey", `["saml:acme","https://idp.test","dana-at-idp"]`, "identityId", dana.Get("id"), "providerId", providerID,
		"issuer", "https://idp.test", "subject", "dana-at-idp"))
	err = host.AssertTrustChange(f.ctx, f.ownerSignIn(), f.tenantID, providerID)
	expectError(t, err, "ACCESS_DENIED", "A root administrator signs in through this connection; only a root administrator can change what it trusts")
	if err := host.AssertTrustChange(f.ctx, f.rootCredential(), f.tenantID, providerID); err != nil {
		t.Fatal(err)
	}
}

func TestFederationSyncRoleMappingsFollowsTeamsThenTheMappedRoles(t *testing.T) {
	f := newAppsOrg(t, nil)
	group := f.group("Engineering")
	err := f.iam.Store.Transaction(f.ctx, func(ctx context.Context, tx core.IamStore) error {
		return federationHost(f).SyncRoleMappings(ctx, tx, RoleMappingSync{TenantID: f.tenantID, ConnectionID: "conn-1",
			GroupID: jsString(group.Get("id")), IdentityIDs: []string{}, RoleIDs: []string{}})
	})
	appsPorted(t, err)
	if err != nil {
		t.Fatal(err)
	}
}

func TestFederationProtocolHostValidatesAttributesAndSessions(t *testing.T) {
	f := newAppsOrg(t, nil)
	host := federationHost(f)
	if host.Store != f.iam.Store {
		t.Fatal("the host's store is not the deployment's")
	}
	principal, err := f.iam.Auth.Authenticate(f.ctx, f.owner)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := host.ValidateSession(f.ctx, principal.Session.Get("id"))
	if err != nil || validated.Identity.Get("id") != f.ownerID {
		t.Fatalf("validateSession: %v %v", validated, err)
	}
	authenticated, err := host.Authenticate(f.ctx, f.owner)
	if err != nil || authenticated.Identity.Get("id") != f.ownerID {
		t.Fatalf("authenticate: %v %v", authenticated, err)
	}
	if err := host.Authorize(f.ctx, f.owner, "iam:groups:read", core.ResourceRef{TenantID: f.tenantID, Type: "iam", ID: f.tenantID}); err != nil {
		t.Fatal(err)
	}
	f.memberIdentity("alice")
	err = host.Authorize(f.ctx, f.token("alice"), "iam:groups:create", core.ResourceRef{TenantID: f.tenantID, Type: "iam", ID: f.tenantID})
	appsCode(t, err, "ACCESS_DENIED")
	// No identity attributes are declared: an empty object validates, anything else does not.
	if _, err := host.ValidateIdentityAttributes(core.NewObject()); err != nil {
		t.Fatal(err)
	}
	if _, err := host.ValidateIdentityAttributes(core.NewObject("department", "eng")); err == nil {
		t.Fatal("an undeclared attribute was accepted")
	}
}
