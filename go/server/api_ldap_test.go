package server

// Port of the server side of tests/ldap.test.ts: base DN normalization, the `ldap` API group (getSettings,
// updateSettings, directory) and the runtime lookups the gateway makes before a bind (tenantForBase,
// resolveBindName). The wire protocol itself is @better-iam/ldap's and is not part of the server.

import (
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

func TestLdapNormalizesBaseDns(t *testing.T) {
	for input, want := range map[string]string{
		"dc=acme, dc=test":           `{"baseDn":"dc=acme,dc=test","normalized":"dc=acme,dc=test"}`,
		" DC=Acme  Corp ,O=Big-Co.X": `{"baseDn":"DC=Acme  Corp,O=Big-Co.X","normalized":"dc=acme corp,o=big-co.x"}`,
		"o=acme":                     `{"baseDn":"o=acme","normalized":"o=acme"}`,
		"dc=people,ou=people":        `{"baseDn":"dc=people,ou=people","normalized":"dc=people,ou=people"}`,
		"cn=a_b.c-d,dc=x9":           `{"baseDn":"cn=a_b.c-d,dc=x9","normalized":"cn=a_b.c-d,dc=x9"}`,
		"x-1=A,y=b":                  `{"baseDn":"x-1=A,y=b","normalized":"x-1=a,y=b"}`,
		"dc=acme,\tdc=test":          `{"baseDn":"dc=acme,dc=test","normalized":"dc=acme,dc=test"}`,
		"dc=acme,dc=test ":           `{"baseDn":"dc=acme,dc=test","normalized":"dc=acme,dc=test"}`,
		"o=a b  c":                   `{"baseDn":"o=a b  c","normalized":"o=a b c"}`,
		"ou=Groups2,dc=acme,dc=test": `{"baseDn":"ou=Groups2,dc=acme,dc=test","normalized":"ou=groups2,dc=acme,dc=test"}`,
	} {
		got, err := NormalizeBaseDn(input)
		if err != nil {
			t.Fatalf("%q: %v", input, err)
		}
		expectInvariantJSON(t, got, want)
	}
	for input, message := range map[any]string{
		"":                       "Enter a base DN such as dc=acme,dc=com",
		"   ":                    "Enter a base DN such as dc=acme,dc=com",
		42.0:                     "Enter a base DN such as dc=acme,dc=com",
		strings.Repeat("a", 513): "Enter a base DN such as dc=acme,dc=com",
		"a=1,b=2,c=3,d=4,e=5,f=6,g=7,h=8,i=9,j=10,k=11": "A base DN has at most 10 components",
		"dc=":           `Base DN components are attr=value with letters, digits, spaces, ".", "_" or "-"`,
		"dc=acme,":      `Base DN components are attr=value with letters, digits, spaces, ".", "_" or "-"`,
		"dc=a\\,b":      `Base DN components are attr=value with letters, digits, spaces, ".", "_" or "-"`,
		"1dc=acme":      `Base DN components are attr=value with letters, digits, spaces, ".", "_" or "-"`,
		"dc=acme-":      `Base DN components are attr=value with letters, digits, spaces, ".", "_" or "-"`,
		"OU=People,o=x": "The base DN cannot itself be ou=people, ou=groups or ou=services",
		"ou=services":   "The base DN cannot itself be ou=people, ou=groups or ou=services",
	} {
		_, err := NormalizeBaseDn(input)
		expectError(t, err, "INVALID_INPUT", message)
	}
}

func TestLdapDefaultSettingsDeriveTheBaseDnFromTheSlug(t *testing.T) {
	for slug, want := range map[any]string{
		"acme":         "o=acme",
		"Acme Corp!":   "o=acme-corp",
		"--x--":        "o=x",
		"!!!":          "o=tenant",
		"café":         "o=caf",
		"a\U0001F600b": "o=a--b",
	} {
		settings := defaultLdapSettings(core.NewObject("id", "t1", "slug", slug))
		if settings.Get("baseDn") != want || settings.Get("normalizedBaseDn") != want {
			t.Fatalf("%q: %s", slug, core.MustStringify(settings))
		}
	}
	expectInvariantJSON(t, defaultLdapSettings(core.NewObject("id", "T-1")),
		`{"id":"T-1","tenantId":"T-1","enabled":false,"baseDn":"o=t-1","normalizedBaseDn":"o=t-1","uid":"email","peopleBind":true,"serviceBind":true,"requireTls":true,"mfaSuffix":"auto","includeServiceAccounts":false,"attributes":[],"groups":"all","groupIds":[],"updatedAt":0,"updatedBy":""}`)
}

type ldapScenario struct {
	*opsFixture
	alice, bob, vpn, engineering *core.Object
	reader                       core.CredentialInput
}

func newLdapScenario(t *testing.T) *ldapScenario {
	t.Helper()
	f := newOpsFixture(t, func(options *BetterIamOptions) {
		options.Permissions = &core.PermissionsConfig{IdentityAttributes: []core.NamedAttribute{{Name: "department", Type: "string"}, {Name: "salary", Type: "number"}}}
	})
	s := &ldapScenario{opsFixture: f, alice: f.member("alice"), bob: f.member("bob")}
	f.put("identities", f.get("identities", jsString(s.alice.Get("id"))).Spread(core.NewObject("attributes", core.NewObject("department", "R&D", "salary", 1.0))))
	s.engineering = f.group("Engineering")
	f.put("groups", s.engineering.Spread(core.NewObject("description", "Builds things")))
	f.put("groupMembers", groupMemberRecord(f.tenantID, jsString(s.engineering.Get("id")), jsString(s.alice.Get("id"))))
	s.vpn = f.put("identities", core.NewObject("id", "svc-"+ID(), "tenantId", f.tenantID, "kind", "service", "name", "vpn", "status", "active", "createdAt", 1.0))
	readers := f.role("Directory readers", "iam:ldap:read")
	reader := f.member("reader")
	f.bind("identity", jsString(reader.Get("id")), jsString(readers.Get("id")))
	s.reader = f.memberCredential("reader")
	return s
}

func (s *ldapScenario) update(credential core.CredentialInput, body *core.Object) (*core.Object, error) {
	out, err := s.iam.API.Ldap.UpdateSettings(s.ctx, credential, Input[apitypes.LdapUpdateSettingsInput](core.NewObject("tenantId", s.tenantID).Assign(body)))
	result, _ := out.Value.(*core.Object)
	return result, err
}

func (s *ldapScenario) directory(credential core.CredentialInput) (*core.Object, error) {
	out, err := s.iam.API.Ldap.Directory(s.ctx, credential, Input[apitypes.LdapDirectoryInput](core.NewObject("tenantId", s.tenantID)))
	result, _ := out.Value.(*core.Object)
	return result, err
}

func TestLdapSettingsDirectoryAndBindNames(t *testing.T) {
	s := newLdapScenario(t)
	runtime := s.iam.Ldap
	aliceID, bobID, vpnID := jsString(s.alice.Get("id")), jsString(s.bob.Get("id")), jsString(s.vpn.Get("id"))
	// Off until turned on, under a base DN derived from the organization.
	initial, err := s.iam.API.Ldap.GetSettings(s.ctx, s.owner, Input[apitypes.LdapGetSettingsInput](core.NewObject("tenantId", s.tenantID)))
	if err != nil {
		t.Fatal(err)
	}
	if member(initial.Value, "enabled") != false || member(initial.Value, "baseDn") != "o="+strings.ToLower(s.tenantID) || member(initial.Value, "updatedAt") != core.Undefined {
		t.Fatalf("initial: %s", core.MustStringify(initial.Value))
	}
	_, err = s.directory(s.owner)
	expectError(t, err, "FEATURE_DISABLED", "The LDAP gateway is off for this organization")

	settings := must(s.update(s.owner, core.NewObject("enabled", true, "baseDn", "dc=acme, dc=test", "includeServiceAccounts", true)))
	expectInvariantJSON(t, settings, `{"tenantId":"`+s.tenantID+`","enabled":true,"baseDn":"dc=acme,dc=test","uid":"email","peopleBind":true,"serviceBind":true,"requireTls":true,"mfaSuffix":"auto","includeServiceAccounts":true,"attributes":[],"groups":"all","groupIds":[],"updatedAt":`+core.NumberString(float64(s.now()))+`,"updatedBy":"`+s.ownerID+`"}`)
	if base := s.get("ldapBases", "dc=acme,dc=test"); base == nil || base.Get("tenantId") != s.tenantID {
		t.Fatalf("base index: %v", base)
	}

	// The gateway finds the tenant by its base DN.
	found := must(runtime.TenantForBase(s.ctx, "dc=acme,dc=test"))
	expectInvariantJSON(t, found, `{"tenantId":"`+s.tenantID+`","tenantName":"Acme","baseDn":"dc=acme,dc=test","normalizedBaseDn":"dc=acme,dc=test","uid":"email","peopleBind":true,"serviceBind":true,"requireTls":true,"mfaSuffix":"auto"}`)
	if missing := must(runtime.TenantForBase(s.ctx, "dc=other,dc=test")); missing != nil {
		t.Fatal("an unknown base DN resolved")
	}
	// People resolve by uid (without regard to case), service accounts by name or ID.
	expectInvariantJSON(t, must(runtime.ResolveBindName(s.ctx, s.tenantID, "person", "ALICE@acme.test")), `{"identityId":"`+aliceID+`","email":"alice@acme.test","mfa":"none"}`)
	if nobody := must(runtime.ResolveBindName(s.ctx, s.tenantID, "person", "nobody@acme.test")); nobody != nil {
		t.Fatal("nobody resolved")
	}
	expectInvariantJSON(t, must(runtime.ResolveBindName(s.ctx, s.tenantID, "service", "VPN")), `{"identityId":"`+vpnID+`"}`)
	expectInvariantJSON(t, must(runtime.ResolveBindName(s.ctx, s.tenantID, "service", vpnID)), `{"identityId":"`+vpnID+`"}`)
	if person := must(runtime.ResolveBindName(s.ctx, s.tenantID, "service", "alice")); person != nil {
		t.Fatal("a person resolved as a service account")
	}
	// MFA: an enrolled authenticator means password + code; required without one cannot be met over LDAP.
	s.put("authMfa", core.NewObject("id", bobID, "tenantId", s.tenantID, "enabled", true, "secret", "sealed"))
	expectInvariantJSON(t, must(runtime.ResolveBindName(s.ctx, s.tenantID, "person", "bob@acme.test")), `{"identityId":"`+bobID+`","email":"bob@acme.test","mfa":"totp"}`)
	tenant := s.get("tenants", s.tenantID)
	s.put("tenants", tenant.Spread(core.NewObject("authPolicy", core.NewObject("requireMfa", true))))
	expectInvariantJSON(t, must(runtime.ResolveBindName(s.ctx, s.tenantID, "person", "alice@acme.test")), `{"identityId":"`+aliceID+`","email":"alice@acme.test","mfa":"unavailable"}`)
	s.put("tenants", tenant)

	// Without iam:ldap:read a person sees only their own entry, and their groups with only them in it.
	alice := s.memberCredential("alice")
	own := must(s.directory(alice))
	if own.Get("scope") != "self" {
		t.Fatalf("scope %v", own.Get("scope"))
	}
	expectInvariantJSON(t, own.Get("people"), `[{"id":"`+aliceID+`","uid":"alice@acme.test","email":"alice@acme.test","name":"alice","emailVerified":true,"attributes":{},"groupIds":["`+jsString(s.engineering.Get("id"))+`"]}]`)
	expectInvariantJSON(t, own.Get("groups"), `[{"id":"`+jsString(s.engineering.Get("id"))+`","name":"Engineering","description":"Builds things","memberIds":["`+aliceID+`"]}]`)
	expectInvariantJSON(t, own.Get("services"), `[]`)
	if reads := s.find("audit", core.NewObject("tenantId", s.tenantID, "action", "ldap:directory:read")); len(reads) != 0 {
		t.Fatal("a self-scoped read was audited")
	}
	// With iam:ldap:read the whole published directory, audited.
	full := must(s.directory(s.reader))
	if full.Get("scope") != "full" || full.Get("tenantName") != "Acme" || full.Get("baseDn") != "dc=acme,dc=test" {
		t.Fatalf("full: %s", core.MustStringify(full))
	}
	var uids []string
	for _, person := range full.Get("people").([]any) {
		uids = append(uids, jsString(member(person, "uid")))
	}
	if strings.Join(uids, ",") != "alice@acme.test,bob@acme.test,owner@acme.test,reader@acme.test" {
		t.Fatalf("people: %v", uids)
	}
	expectInvariantJSON(t, full.Get("services"), `[{"id":"`+vpnID+`","name":"vpn","kind":"service","groupIds":[]}]`)
	reads := s.find("audit", core.NewObject("tenantId", s.tenantID, "action", "ldap:directory:read"))
	if len(reads) != 1 {
		t.Fatalf("directory reads audited: %d", len(reads))
	}
	expectInvariantJSON(t, reads[0].Get("metadata"), `{"people":4,"groups":1}`)

	// Only declared identity attributes can be published; they appear on people's entries.
	_, err = s.update(s.owner, core.NewObject("attributes", []any{"title"}))
	expectError(t, err, "INVALID_INPUT", "title is not a declared identity attribute LDAP can publish")
	_, err = s.update(s.owner, core.NewObject("attributes", "department"))
	expectError(t, err, "INVALID_INPUT", "attributes must list at most 64 identity attributes")
	must(s.update(s.owner, core.NewObject("attributes", []any{"department", "department"}, "uid", "localPart")))
	full = must(s.directory(s.reader))
	first := full.Get("people").([]any)[0]
	if member(first, "uid") != "alice" || core.MustStringify(member(first, "attributes")) != `{"department":"R&D"}` {
		t.Fatalf("first person: %s", core.MustStringify(first))
	}
	expectInvariantJSON(t, must(runtime.ResolveBindName(s.ctx, s.tenantID, "person", "alice")), `{"identityId":"`+aliceID+`","email":"alice@acme.test","mfa":"none"}`)
	// Selected groups only.
	must(s.update(s.owner, core.NewObject("groups", "selected")))
	expectInvariantJSON(t, must(s.directory(s.reader)).Get("groups"), `[]`)
	must(s.update(s.owner, core.NewObject("groupIds", []any{s.engineering.Get("id")})))
	if groups := must(s.directory(s.reader)).Get("groups").([]any); len(groups) != 1 {
		t.Fatalf("groups: %d", len(groups))
	}
	_, err = s.update(s.owner, core.NewObject("groupIds", []any{"missing"}))
	expectError(t, err, "NOT_FOUND", "Resource not found")
	// Validation of the other fields.
	_, err = s.update(s.owner, core.NewObject("uid", "name"))
	expectError(t, err, "INVALID_INPUT", "uid must be 'email', 'localPart' or 'id'")
	_, err = s.update(s.owner, core.NewObject("mfaSuffix", "always"))
	expectError(t, err, "INVALID_INPUT", "mfaSuffix must be 'auto' or 'never'")
	_, err = s.update(s.owner, core.NewObject("requireTls", "yes"))
	expectError(t, err, "INVALID_INPUT", "requireTls must be a boolean")
	_, err = s.update(s.owner, core.NewObject("groups", "some"))
	expectError(t, err, "INVALID_INPUT", "groups must be 'all' or 'selected'")
	_, err = s.update(alice, core.NewObject("enabled", false))
	expectCode(t, err, "ACCESS_DENIED")
	_, err = s.iam.API.Ldap.GetSettings(s.ctx, s.owner, Input[apitypes.LdapGetSettingsInput](core.NewObject()))
	expectError(t, err, "INVALID_INPUT", "Invalid tenantId")

	// A base DN belongs to one organization.
	other := s.tenantID
	s.tenantID = "beta-" + ID()
	s.put("tenants", core.NewObject("id", s.tenantID, "tenantId", s.tenantID, "name", "Beta", "type", "organization", "parentId", s.rootTenantID, "status", "active", "createdAt", 1.0))
	_, err = s.update(s.rootCredential(), core.NewObject("enabled", true, "baseDn", "DC=Acme,DC=Test"))
	expectError(t, err, "LDAP_BASE_TAKEN", "Another organization publishes its directory under this base DN")
	s.tenantID = other

	// Moving the base DN moves the index entry; turning the gateway off removes it.
	must(s.update(s.owner, core.NewObject("baseDn", "o=acme")))
	if s.get("ldapBases", "dc=acme,dc=test") != nil || s.get("ldapBases", "o=acme") == nil {
		t.Fatal("the base index did not move")
	}
	if must(runtime.TenantForBase(s.ctx, "dc=acme,dc=test")) != nil {
		t.Fatal("the old base DN still resolves")
	}
	must(s.update(s.owner, core.NewObject("enabled", false)))
	if s.get("ldapBases", "o=acme") != nil || must(runtime.TenantForBase(s.ctx, "o=acme")) != nil {
		t.Fatal("a disabled gateway is still published")
	}
	// An inactive organization is not served either.
	must(s.update(s.owner, core.NewObject("enabled", true)))
	s.put("tenants", s.get("tenants", s.tenantID).Spread(core.NewObject("status", "suspended")))
	if must(runtime.TenantForBase(s.ctx, "o=acme")) != nil {
		t.Fatal("a suspended organization is published")
	}
}
