package scim

// Port of tests/scim.test.ts: SCIM tenant isolation and provisioning.

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

type isolationFixture struct {
	t       *testing.T
	store   core.IamStore
	service *Service
	a, b    connectionCredential
}

var admin = core.CredentialInput{Token: "admin"}

func adminOnly(credential core.CredentialInput) error {
	if credential.Token != "admin" {
		return core.NewIamError("FORBIDDEN", "Forbidden", 403)
	}
	return nil
}

func seedTenants(t *testing.T, store core.IamStore) {
	t.Helper()
	for _, id := range []string{"root", "a", "b"} {
		kind, parent := "organization", any("root")
		if id == "root" {
			kind, parent = "root", nil
		}
		insert(t, store, "tenants", obj("id", id, "tenantId", id, "name", id, "type", kind, "parentId", parent, "status", "active", "createdAt", wallClock()))
	}
}

func newIsolationFixture(t *testing.T) *isolationFixture {
	t.Helper()
	store := newStore(t)
	seedTenants(t, store)
	service := must(NewService(Config{
		Store: store,
		Authenticate: func(_ context.Context, credential core.CredentialInput) (string, error) {
			if err := adminOnly(credential); err != nil {
				return "", err
			}
			return "administrator", nil
		},
		Authorize: func(_ context.Context, credential core.CredentialInput, _ string, _ core.ResourceRef) error {
			return adminOnly(credential)
		},
		MapAttributes: func(user ProvisionedUser) *core.Object {
			attributes := core.NewObject()
			if user.Title != nil {
				attributes.Set("title", *user.Title)
			}
			if department, isText := member(user.Enterprise, "department").(string); isText {
				attributes.Set("department", department)
			}
			if attributes.Len() == 0 {
				return nil
			}
			return attributes
		},
		ValidateIdentityAttributes: func(attributes *core.Object) (*core.Object, error) {
			for _, key := range attributes.Keys() {
				if key != "title" && key != "department" {
					return nil, core.NewIamError("INVALID_INPUT", "Attribute "+key+" is not declared")
				}
			}
			return attributes, nil
		},
	}))
	f := &isolationFixture{t: t, store: store, service: service}
	f.a = credentialOf(must(service.CreateConnection(bg, admin, CreateConnectionInput{TenantID: "a", Name: "A"})))
	f.b = credentialOf(must(service.CreateConnection(bg, admin, CreateConnectionInput{TenantID: "b", Name: "B"})))
	return f
}

func (f *isolationFixture) request(connection connectionCredential, resource, method string, body any, headers ...map[string]string) answer {
	f.t.Helper()
	var extra map[string]string
	if len(headers) > 0 {
		extra = headers[0]
	}
	return scimCall(f.t, f.service, "https://iam.test", connection, resource, method, body, extra)
}

func TestScopesTokensResourcesAndSameEmailAccountsToTheConnectionTenant(t *testing.T) {
	f := newIsolationFixture(t)
	createA := f.request(f.a, "Users", "POST", obj("userName", "same@example.test", "active", true))
	if createA.status != 201 {
		t.Fatalf("create A: %d %s", createA.status, show(createA.body))
	}
	createB := f.request(f.b, "Users", "POST", obj("userName", "same@example.test", "active", true))
	if createB.status != 201 || createB.get("id") == createA.get("id") {
		t.Fatalf("create B: %d", createB.status)
	}
	if got := f.request(f.b, "Users/"+createA.get("id").(string), "", nil); got.status != 404 {
		t.Fatalf("cross-tenant read: %d", got.status)
	}
	if got := f.request(connectionCredential{path: f.a.path, token: f.b.token}, "Users", "", nil); got.status != 401 {
		t.Fatalf("foreign token: %d", got.status)
	}
	if count := len(find(t, f.store, "identities", obj("email", "same@example.test"))); count != 2 {
		t.Fatalf("identities: %d", count)
	}
	for _, row := range find(t, f.store, "scimConnections", nil) {
		if strings.Contains(show(row), f.a.token) {
			t.Fatal("the token is stored in plaintext")
		}
	}
}

func TestMapsTheTitleAndEnterpriseExtensionToDeclaredIdentityAttributes(t *testing.T) {
	f := newIsolationFixture(t)
	created := f.request(f.a, "Users", "POST", obj(
		"schemas", list(UserSchema, EnterpriseSchema),
		"userName", "mapped@example.test",
		"title", "Engineer",
		EnterpriseSchema, obj("department", "Platform", "manager", obj("value", "boss", "displayName", "Boss")),
	))
	if created.status != 201 {
		t.Fatalf("create: %d %s", created.status, show(created.body))
	}
	if created.get("title") != "Engineer" {
		t.Fatal("title")
	}
	sameJSON(t, created.get(EnterpriseSchema), obj("department", "Platform", "manager", obj("value", "boss", "displayName", "Boss")))
	if schemas := created.get("schemas").([]any); len(schemas) != 2 || schemas[1] != EnterpriseSchema {
		t.Fatalf("schemas: %v", schemas)
	}
	link := get(t, f.store, "scimUsers", created.get("id").(string))
	identityID := link.Get("identityId").(string)
	sameJSON(t, get(t, f.store, "identities", identityID).Get("attributes"), obj("title", "Engineer", "department", "Platform"))
	// PUT replaces the mapping; unsupported enterprise fields are rejected.
	replaced := f.request(f.a, "Users/"+created.get("id").(string), "PUT", obj("userName", "mapped@example.test", "title", "Lead"))
	if replaced.status != 200 {
		t.Fatalf("put: %d %s", replaced.status, show(replaced.body))
	}
	sameJSON(t, get(t, f.store, "identities", identityID).Get("attributes"), obj("title", "Lead"))
	rejected := f.request(f.a, "Users/"+created.get("id").(string), "PUT", obj("userName", "mapped@example.test", EnterpriseSchema, obj("badge", "gold")))
	if rejected.status != 400 {
		t.Fatalf("badge: %d", rejected.status)
	}
}

func TestDeactivationRevokesLocalAndAssumedSessionsWhilePreservingAnotherTenant(t *testing.T) {
	f := newIsolationFixture(t)
	user := f.request(f.a, "Users", "POST", obj("userName", "user@example.test"))
	link := get(t, f.store, "scimUsers", user.get("id").(string))
	identityID := link.Get("identityId")
	insert(t, f.store, "sessions",
		obj("id", "local", "tenantId", "a", "identityId", identityID),
		obj("id", "assumed", "tenantId", "b", "identityId", "role-user", "originalIdentityId", identityID),
		obj("id", "other", "tenantId", "b", "identityId", "other-user"),
	)
	patched := f.request(f.a, "Users/"+user.get("id").(string), "PATCH", patchOp(obj("op", "replace", "path", "active", "value", false)))
	if patched.status != 200 || patched.get("active") != false {
		t.Fatalf("patch: %d %s", patched.status, show(patched.body))
	}
	if get(t, f.store, "sessions", "local") != nil || get(t, f.store, "sessions", "assumed") != nil {
		t.Fatal("sessions survived")
	}
	if get(t, f.store, "sessions", "other") == nil {
		t.Fatal("another tenant's session was revoked")
	}
	if get(t, f.store, "identities", identityID.(string)).Get("status") != "disabled" {
		t.Fatal("identity still active")
	}
}

func TestSupportsGroupPatchAndRejectsNestedOrForeignMembersAtomically(t *testing.T) {
	f := newIsolationFixture(t)
	first := f.request(f.a, "Users", "POST", obj("userName", "one@example.test"))
	second := f.request(f.a, "Users", "POST", obj("userName", "two@example.test"))
	foreign := f.request(f.b, "Users", "POST", obj("userName", "foreign@example.test"))
	group := f.request(f.a, "Groups", "POST", obj("displayName", "Engineers", "members", list(obj("value", first.get("id")))))
	groupPath := "Groups/" + group.get("id").(string)
	if got := f.request(f.a, groupPath, "PATCH", patchOp(obj("op", "add", "path", "members", "value", list(obj("value", second.get("id")))))); got.status != 200 {
		t.Fatalf("add: %d %s", got.status, show(got.body))
	}
	if got := f.request(f.a, groupPath, "PATCH", patchOp(obj("op", "add", "path", "members", "value", list(obj("value", foreign.get("id")))))); got.status != 400 {
		t.Fatalf("foreign: %d", got.status)
	}
	if got := f.request(f.a, groupPath, "PATCH", patchOp(obj("op", "add", "path", "members", "value", list(obj("value", group.get("id"), "type", "Group"))))); got.status != 400 {
		t.Fatalf("nested: %d", got.status)
	}
	if members := f.request(f.a, groupPath, "", nil).get("members").([]any); len(members) != 2 {
		t.Fatalf("members: %d", len(members))
	}
	if got := f.request(f.a, groupPath, "PATCH", patchOp(obj("op", "remove", "path", `members[value eq "`+first.get("id").(string)+`"]`))); got.status != 200 {
		t.Fatalf("remove: %d %s", got.status, show(got.body))
	}
	if count := len(find(t, f.store, "groupMembers", nil)); count != 1 {
		t.Fatalf("groupMembers: %d", count)
	}
}

func TestRejectsOwnerChangesStaleETagsAndEmailBasedAccountTakeover(t *testing.T) {
	f := newIsolationFixture(t)
	user := f.request(f.a, "Users", "POST", obj("userName", "owner@example.test"))
	userPath := "Users/" + user.get("id").(string)
	if got := f.request(f.a, userPath, "PUT", obj("userName", "owner@example.test"), map[string]string{"if-match": `W/"0"`}); got.status != 412 {
		t.Fatalf("stale etag: %d", got.status)
	}
	link := get(t, f.store, "scimUsers", user.get("id").(string))
	identity := get(t, f.store, "identities", link.Get("identityId").(string))
	put(t, f.store, "identities", identity.Spread(obj("owner", true)))
	if got := f.request(f.a, userPath, "DELETE", nil); got.status != 403 {
		t.Fatalf("owner delete: %d", got.status)
	}
	second := credentialOf(must(f.service.CreateConnection(bg, admin, CreateConnectionInput{TenantID: "a", Name: "another"})))
	if got := f.request(second, "Users", "POST", obj("userName", "owner@example.test")); got.status != 409 {
		t.Fatalf("takeover: %d", got.status)
	}
}

func TestFiltersAndPagesHonestlyAndRejectsRevokedOrSuspendedConnections(t *testing.T) {
	f := newIsolationFixture(t)
	for _, userName := range []string{"a@example.test", "b@example.test"} {
		if got := f.request(f.a, "Users", "POST", obj("userName", userName)); got.status != 201 {
			t.Fatalf("create: %d", got.status)
		}
	}
	filtered := f.request(f.a, "Users?filter="+url.QueryEscape(`userName eq "A@example.test"`), "", nil)
	if filtered.get("totalResults") != 1.0 {
		t.Fatalf("filtered: %s", show(filtered.body))
	}
	page := f.request(f.a, "Users?startIndex=1&count=1", "", nil)
	if page.get("itemsPerPage") != 1.0 || page.get("totalResults") != 2.0 {
		t.Fatalf("page: %s", show(page.body))
	}
	if got := f.request(f.a, "Users?filter="+url.QueryEscape(`userName eq "a" or bogus(`), "", nil); got.status != 400 {
		t.Fatalf("bad filter: %d", got.status)
	}
	discovery := f.request(f.a, "ServiceProviderConfig", "", nil)
	if discovery.get("bulk", "supported") != true || discovery.get("bulk", "maxOperations") != 100.0 || discovery.get("sort", "supported") != true {
		t.Fatalf("discovery: %s", show(discovery.body))
	}
	ok(t, f.service.RevokeConnection(bg, admin, "a", f.a.id))
	if got := f.request(f.a, "Users", "", nil); got.status != 401 {
		t.Fatalf("revoked: %d", got.status)
	}
	root := get(t, f.store, "tenants", "root")
	put(t, f.store, "tenants", root.Spread(obj("status", "suspended")))
	if got := f.request(f.b, "Users", "", nil); got.status != 401 {
		t.Fatalf("suspended: %d", got.status)
	}
}

func TestRequiresAdministratorCredentialsToProvisionConnections(t *testing.T) {
	f := newIsolationFixture(t)
	_, err := f.service.CreateConnection(bg, core.CredentialInput{Token: "forged"}, CreateConnectionInput{TenantID: "a", Name: "forged"})
	if known, isKnown := err.(*core.IamError); !isKnown || known.Status != 403 {
		t.Fatalf("forged: %v", err)
	}
	if _, err := ParseScimFilter(`active eq "false"`); err == nil {
		t.Fatal("a string comparison of active must fail")
	}
}

func TestRoundtripsSupportedProfileAttributesAndTreatsExternalIDsAsCaseExact(t *testing.T) {
	f := newIsolationFixture(t)
	name := obj("givenName", "Ada", "familyName", "Lovelace")
	emails := list(obj("value", "ada@example.test", "primary", true, "type", "work"))
	created := f.request(f.a, "Users", "POST", obj("userName", "profile", "externalId", "CaseSensitiveID", "name", name, "emails", emails))
	if created.status != 201 {
		t.Fatalf("create: %d %s", created.status, show(created.body))
	}
	sameJSON(t, created.get("name"), name)
	sameJSON(t, created.get("emails"), emails)
	wrongCase := f.request(f.a, "Users?filter="+url.QueryEscape(`externalId eq "casesensitiveid"`), "", nil)
	if wrongCase.get("totalResults") != 0.0 {
		t.Fatalf("case-exact: %s", show(wrongCase.body))
	}
	patched := f.request(f.a, "Users/"+created.get("id").(string), "PATCH", patchOp(obj("op", "replace", "path", "displayName", "value", "Ada")))
	sameJSON(t, patched.get("emails"), emails)
}
