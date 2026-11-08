package saml

// Port of the SAML cases of tests/security-federation.test.ts: accounts linked through one sign-in provider stay out
// of reach of every other trust anchor (a SAML connection given another provider's ID, a connection deleted and
// recreated under the same ID, an administrator who swaps a connection's IdP certificates).

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

// orgFixture is tests/support/organization.ts organizationFixture: a bootstrapped platform with one organization
// ("Acme") whose owner is set up, a controllable clock, and sessions that last seven days.
type orgFixture struct {
	t        *testing.T
	ctx      context.Context
	iam      *server.BetterIam
	clock    *atomic.Int64
	tenantID string
	ownerID  string
}

func newOrgFixture(t *testing.T) *orgFixture {
	t.Helper()
	clock := &atomic.Int64{}
	clock.Store(time.Now().UnixMilli())
	week := int64(7 * 86_400_000)
	now := func() int64 { return clock.Load() }
	iam, err := server.New(&server.BetterIamOptions{
		Database: newTestStore(t), Secret: "organization-fixture-secret-with-32-characters", BaseURL: "http://localhost:3000",
		WallClock:      now,
		Authentication: &auth.Options{Now: now, SessionLifetimeMs: &week, SessionIdleTimeoutMs: &week},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(iam.Close)
	f := &orgFixture{t: t, ctx: context.Background(), iam: iam, clock: clock}
	if err := iam.Initialize(f.ctx); err != nil {
		t.Fatal(err)
	}
	root, err := iam.Bootstrap(f.ctx, core.NewObject("email", "root@example.test", "name", "Root", "password", "a strong root test password"))
	if err != nil {
		t.Fatal(err)
	}
	rootTenantID := jsString(member(root.Get("tenant"), "id"))
	rootID := jsString(member(root.Get("identity"), "id"))
	err = iam.Store.Transaction(f.ctx, func(ctx context.Context, tx core.IamStore) error {
		authorities, err := tx.Find(ctx, "grantAuthorities", core.NewObject("tenantId", rootTenantID, "identityId", rootID), nil)
		if err != nil {
			return err
		}
		if len(authorities) == 0 {
			return errors.New("root has no grant authority")
		}
		f.tenantID = server.ID()
		realm := core.NewObject("id", f.tenantID, "tenantId", f.tenantID, "name", "Acme", "type", "organization",
			"parentId", rootTenantID, "status", "active", "createdAt", float64(now()))
		if _, err := tx.Insert(ctx, "tenants", realm); err != nil {
			return err
		}
		authority, err := tx.Insert(ctx, "grantAuthorities", core.NewObject("id", server.ID(), "tenantId", f.tenantID,
			"identityId", "pending", "parentAuthorityId", authorities[0].Get("id"), "ceiling", server.All(), "revoked", false))
		if err != nil {
			return err
		}
		owner, err := iam.Auth.CreateIdentity(ctx, tx, auth.CreateIdentityInput{TenantID: f.tenantID, Email: "owner@acme.test",
			Name: "Owner", Password: "a strong tenant owner password", HasPassword: true, Owner: true, EmailVerified: true})
		if err != nil {
			return err
		}
		f.ownerID = jsString(owner.Get("id"))
		return iam.Context.OwnerSetup(ctx, tx, realm, owner, authority)
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *orgFixture) advance(ms int64) { f.clock.Add(ms) }

func (f *orgFixture) signInAs(email, password string) core.CredentialInput {
	f.t.Helper()
	out, err := f.iam.API.Auth.SignIn(f.ctx, server.Input[apitypes.AuthSignInInput](core.NewObject("tenantId", f.tenantID,
		"email", email, "password", password)))
	if err != nil {
		f.t.Fatal(err)
	}
	token, ok := member(out.Value, "token").(string)
	if !ok {
		f.t.Fatalf("unexpected sign-in answer %v", core.MustStringify(out.Value))
	}
	return core.CredentialInput{Token: token}
}

func (f *orgFixture) ownerSignIn() core.CredentialInput {
	return f.signInAs("owner@acme.test", "a strong tenant owner password")
}

func (f *orgFixture) signIn(name string) core.CredentialInput {
	return f.signInAs(name+"@acme.test", "a strong "+name+" password")
}

func (f *orgFixture) member(name string) *core.Object {
	f.t.Helper()
	out, err := f.iam.API.Identities.Create(f.ctx, f.ownerSignIn(), server.Input[apitypes.IdentitiesCreateInput](core.NewObject(
		"tenantId", f.tenantID, "email", name+"@acme.test", "name", name, "password", "a strong "+name+" password")))
	if err != nil {
		f.t.Fatal(err)
	}
	return out.Value.(*core.Object)
}

func (f *orgFixture) insert(collection string, record *core.Object) {
	f.t.Helper()
	if err := f.iam.Store.Transaction(f.ctx, func(ctx context.Context, tx core.IamStore) error {
		_, err := tx.Insert(ctx, collection, record)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
}

// signedInAs is the identity a sign-in result's session belongs to.
func (f *orgFixture) signedInAs(result any, err error) string {
	f.t.Helper()
	if err != nil {
		f.t.Fatal(err)
	}
	token, _ := member(result, "token").(string)
	out, err := f.iam.API.Auth.GetSession(f.ctx, core.CredentialInput{Token: token}, server.Input[apitypes.AuthGetSessionInput](nil))
	if err != nil {
		f.t.Fatal(err)
	}
	return jsString(member(member(out.Value, "identity"), "id"))
}

// unsolicitedResponse is a signed, unsolicited (IdP-initiated) response.
func unsolicitedResponse(t *testing.T, connection *core.Object, key keyPair, issuer, nameID, email string) string {
	now := iso(nowMs())
	expires := iso(nowMs() + 120000)
	acs, entity := str(connection, "acsUrl"), str(connection, "entityId")
	attributes := ""
	if email != "" {
		attributes = `<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>` + email + `</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`
	}
	assertion := `<saml:Assertion xmlns:saml="` + assertionNS + `" ID="_` + randomUUID() + `" Version="2.0" IssueInstant="` + now + `"><saml:Issuer>` + issuer + `</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">` + nameID + `</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="` + acs + `" NotOnOrAfter="` + expires + `"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="` + iso(nowMs()-1000) + `" NotOnOrAfter="` + expires + `"><saml:AudienceRestriction><saml:Audience>` + entity + `</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="` + now + `" SessionIndex="session"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` + attributes + `</saml:Assertion>`
	document := `<samlp:Response xmlns:samlp="` + protocolNS + `" xmlns:saml="` + assertionNS + `" ID="_` + randomUUID() + `" Version="2.0" IssueInstant="` + now + `" Destination="` + acs + `"><saml:Issuer>` + issuer + `</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` + sign(t, assertion, "Assertion", key) + `</samlp:Response>`
	return b64(sign(t, document, "Response", key))
}

func connectionInput(tenantID, id, certificate, issuer string) *core.Object {
	return core.NewObject("tenantId", tenantID, "id", id, "name", "Acme IdP", "entryPoint", "https://idp.test/login",
		"idpIssuer", issuer, "idpCertificates", []any{certificate}, "trustedEmailDomains", []any{"acme.test"}, "allowIdpInitiated", true)
}

func federationSetup(t *testing.T) (*orgFixture, *SamlService) {
	f := newOrgFixture(t)
	sp := generate(t, "iam.test")
	options := HostOptions(f.iam)
	options.ServiceProvider = &SamlServiceProvider{BaseURL: "https://iam.test", PrivateKey: sp.private, PublicCertificate: sp.cert}
	return f, must(CreateSamlService(options))
}

func TestSamlNeverReachesAccountsLinkedThroughAnotherProviderWithTheSameID(t *testing.T) {
	f, service := federationSetup(t)
	attacker := generate(t, "attacker.test")
	// The owner signs in with GitHub through a deployment OAuth connection named "github".
	f.insert("externalIdentities", core.NewObject("id", randomUUID(), "tenantId", f.tenantID,
		"uniqueKey", `["github","https://github.com","1234"]`, "identityId", f.ownerID, "providerId", "github",
		"issuer", "https://github.com", "subject", "1234"))
	owner := f.ownerSignIn()
	connection := must(service.CreateConnection(f.ctx, owner, connectionInput(f.tenantID, "github", attacker.cert, "https://github.com")))
	_, err := service.IdpInitiated(f.ctx, "github", unsolicitedResponse(t, connection, attacker, "https://github.com", "1234", "owner@acme.test"))
	if codeOf(err) != "ACCOUNT_LINK_REQUIRED" {
		t.Fatalf("expected ACCOUNT_LINK_REQUIRED, got %v", err)
	}
}

func TestSamlUnlinksAccountsWhenAConnectionIsDeleted(t *testing.T) {
	f, service := federationSetup(t)
	idp := generate(t, "idp.test")
	attacker := generate(t, "attacker.test")
	owner := f.ownerSignIn()
	first := must(service.CreateConnection(f.ctx, owner, connectionInput(f.tenantID, "acme", idp.cert, "https://idp.test")))
	employee := f.signedInAs(service.IdpInitiated(f.ctx, "acme", unsolicitedResponse(t, first, idp, "https://idp.test", "employee-7", "emp7@acme.test")))
	if again := f.signedInAs(service.IdpInitiated(f.ctx, "acme", unsolicitedResponse(t, first, idp, "https://idp.test", "employee-7", "emp7@acme.test"))); again != employee {
		t.Fatalf("second sign-in reached %s, want %s", again, employee)
	}
	if err := service.DeleteConnection(f.ctx, owner, f.tenantID, "acme"); err != nil {
		t.Fatal(err)
	}
	if links := must(f.iam.Store.Find(f.ctx, "externalIdentities", core.NewObject("tenantId", f.tenantID), nil)); len(links) != 0 {
		t.Fatalf("links left: %d", len(links))
	}
	second := must(service.CreateConnection(f.ctx, owner, connectionInput(f.tenantID, "acme", attacker.cert, "https://idp.test")))
	_, err := service.IdpInitiated(f.ctx, "acme", unsolicitedResponse(t, second, attacker, "https://idp.test", "employee-7", "emp7@acme.test"))
	if codeOf(err) != "ACCOUNT_LINK_REQUIRED" {
		t.Fatalf("expected ACCOUNT_LINK_REQUIRED, got %v", err)
	}
}

func TestSamlLetsOnlyARecentOwnerChangeWhatAnOwnersConnectionTrusts(t *testing.T) {
	f, service := federationSetup(t)
	idp := generate(t, "idp.test")
	attacker := generate(t, "attacker.test")
	owner := f.ownerSignIn()
	connection := must(service.CreateConnection(f.ctx, owner, connectionInput(f.tenantID, "acme", idp.cert, "https://idp.test")))
	record := must(f.iam.Store.Get(f.ctx, "samlConnections", "acme"))
	providerKey := str(record, "providerKey")
	f.insert("externalIdentities", core.NewObject("id", randomUUID(), "tenantId", f.tenantID,
		"uniqueKey", core.MustStringify([]any{providerKey, "https://idp.test", "owner-at-idp"}), "identityId", f.ownerID,
		"providerId", providerKey, "issuer", "https://idp.test", "subject", "owner-at-idp"))
	// A delegated administrator of SAML connections.
	dana := f.member("dana")
	role := must(f.iam.API.Roles.Create(f.ctx, owner, server.Input[apitypes.RolesCreateInput](core.NewObject("tenantId", f.tenantID,
		"name", "SSO admin", "permissions", []any{"iam:saml:connections:read", "iam:saml:connections:update", "iam:saml:connections:create"}))))
	must(f.iam.API.Bindings.Create(f.ctx, owner, server.Input[apitypes.BindingsCreateInput](core.NewObject("tenantId", f.tenantID,
		"roleId", member(role.Value, "id"), "subjectType", "identity", "subjectId", dana.Get("id")))))
	danaSession := f.signIn("dana")
	update := func(credential core.CredentialInput, extra ...any) (*core.Object, error) {
		input := core.NewObject("tenantId", f.tenantID, "connectionId", "acme")
		for i := 0; i < len(extra); i += 2 {
			input.Set(extra[i].(string), extra[i+1])
		}
		return service.UpdateConnection(f.ctx, credential, input)
	}
	swap := []any{idp.cert, attacker.cert}
	if _, err := update(danaSession, "idpCertificates", swap); codeOf(err) != "ACCESS_DENIED" {
		t.Fatalf("certificate swap: %v", err)
	}
	for _, change := range [][]any{{"idpIssuer", "https://evil.test"}, {"trustedEmailDomains", []any{"acme.test", "evil.test"}}} {
		if _, err := update(danaSession, change...); codeOf(err) != "ACCESS_DENIED" {
			t.Fatalf("%v: %v", change, err)
		}
	}
	// Nothing that widens trust went through; the owner cannot be signed in with the attacker's key.
	if _, err := service.IdpInitiated(f.ctx, "acme", unsolicitedResponse(t, connection, attacker, "https://idp.test", "owner-at-idp", "")); err == nil {
		t.Fatal("attacker signed in as the owner")
	}
	// Renaming changes no trust, so the delegated administrator may.
	renamed, err := update(danaSession, "name", "Acme SSO")
	if err != nil || renamed.Get("name") != "Acme SSO" {
		t.Fatalf("rename: %v %v", renamed, err)
	}
	// The owner may, but only with a recent sign-in.
	f.advance(10 * 60_000)
	if _, err := update(owner, "idpCertificates", swap); codeOf(err) != "RECENT_AUTH_REQUIRED" {
		t.Fatalf("stale owner: %v", err)
	}
	fresh := f.ownerSignIn()
	updated, err := update(fresh, "idpCertificates", swap)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := updated.Get("certificates").([]any); !ok {
		t.Fatal("no certificates")
	}
}
