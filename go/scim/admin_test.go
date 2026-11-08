package scim

// Port of tests/scim-admin.test.ts: the SCIM connection administration routes, mounted on the IAM handler.

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

const fixtureOrigin = "http://localhost:3000"

type mountedFixture struct {
	*orgFixture
	service *Service
}

func newMounted(t *testing.T) *mountedFixture {
	t.Helper()
	f := newOrgFixture(t)
	config := hostConfig(f.iam)
	config.BasePath = "/api/iam/scim/v2"
	config.AdminBasePath = "/api/iam/scim-admin"
	service := must(NewService(config))
	f.iam.UseProtocol(server.ProtocolService{BasePath: service.BasePath, Handler: service.Handler})
	return &mountedFixture{orgFixture: f, service: service}
}

type envelope struct {
	status       int
	cacheControl string
	body         *core.Object
}

func (e envelope) data() any { return e.body.Get("data") }

func (e envelope) errorCode() any { return member(e.body.Get("error"), "code") }

func decodeServer(t *testing.T, response *server.Response) answer {
	t.Helper()
	result := answer{status: response.Status, header: response.Header}
	if len(response.Body) > 0 {
		result.body = must(core.ParseJSON(response.Body))
	}
	return result
}

// call is a console-style JSON call to the administration API through the IAM handler.
func (m *mountedFixture) call(route string, body any, token string, headers map[string]string, method string) envelope {
	m.t.Helper()
	if method == "" {
		method = "POST"
	}
	if token == "" {
		token = m.owner.Token
	}
	var payload any = body
	if method == "GET" {
		payload = nil
	}
	request := httptest.NewRequest(method, fixtureOrigin+"/api/iam/scim-admin/"+route, jsonBody(payload))
	request.Header.Set("content-type", "application/json")
	request.Header.Set("x-better-iam", "1")
	request.Header.Set("authorization", "Bearer "+token)
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response := decodeServer(m.t, m.iam.Handle(request))
	return envelope{status: response.status, cacheControl: response.header.Get("cache-control"), body: response.object()}
}

// scim is an IdP request to the protocol endpoint, authenticated with the connection token.
func (m *mountedFixture) scim(connection connectionCredential, resource, method string, body any) answer {
	m.t.Helper()
	if method == "" {
		method = "GET"
	}
	request := httptest.NewRequest(method, fixtureOrigin+connection.path+"/"+resource, jsonBody(body))
	request.Header.Set("authorization", "Bearer "+connection.token)
	request.Header.Set("content-type", "application/scim+json")
	return decodeServer(m.t, m.iam.Handle(request))
}

func TestAdminCreatesListsMapsRotatesAndRevokesConnections(t *testing.T) {
	m := newMounted(t)
	tenantID := m.tenantID
	created := m.call("connections/create", obj("tenantId", tenantID, "name", "Okta"), "", nil, "")
	if created.status != 200 || created.cacheControl != "no-store" {
		t.Fatalf("create: %d %s %s", created.status, created.cacheControl, show(created.body))
	}
	data := created.data().(*core.Object)
	connection := connectionCredential{id: data.Get("id").(string), token: data.Get("token").(string), path: data.Get("path").(string)}
	if data.Get("tenantId") != tenantID || connection.path != "/api/iam/scim/v2/"+connection.id {
		t.Fatalf("connection: %s", show(data))
	}

	listed := m.call("connections/list", obj("tenantId", tenantID), "", nil, "")
	rows := listed.data().([]any)
	if len(rows) != 1 {
		t.Fatalf("list: %s", show(listed.body))
	}
	matches(t, rows[0].(*core.Object), "id", connection.id, "name", "Okta", "users", 0, "groups", 0, "revoked", false)
	if strings.Contains(show(listed.body), connection.token) || rows[0].(*core.Object).Has("tokenHash") {
		t.Fatal("the token leaked")
	}

	// The IdP provisions through the protocol endpoint mounted on the same handler.
	pushed := m.scim(connection, "Users", "POST", obj("userName", "dev@acme.test"))
	if pushed.status != 201 {
		t.Fatalf("push: %d %s", pushed.status, show(pushed.body))
	}
	user := pushed.get("id").(string)
	engineering := m.scim(connection, "Groups", "POST", obj("displayName", "Engineering", "externalId", "eng", "members", list(obj("value", user)))).get("id").(string)
	admins := m.scim(connection, "Groups", "POST", obj("displayName", "Admins")).get("id").(string)
	if users := m.scim(connection, "Users", "", nil); users.get("totalResults") != 1.0 {
		t.Fatalf("users: %s", show(users.body))
	}

	groups := m.call("connections/groups", obj("tenantId", tenantID, "connectionId", connection.id), "", nil, "").data().([]any)
	if len(groups) != 2 {
		t.Fatalf("groups: %s", show(groups))
	}
	first, second := groups[0].(*core.Object), groups[1].(*core.Object)
	sameJSON(t, first, obj("id", admins, "groupId", first.Get("groupId"), "displayName", "Admins", "members", 0, "roleIds", list()))
	sameJSON(t, second, obj("id", engineering, "groupId", second.Get("groupId"), "displayName", "Engineering", "externalId", "eng", "members", 1, "roleIds", list()))
	localGroupID := second.Get("groupId").(string)

	readers := m.record(m.iam.API.Roles.Create(m.ctx, m.owner, server.Input[apitypes.RolesCreateInput](obj("tenantId", tenantID, "name", "Readers", "permissions", list("documents:read")))))
	readersID := readers.Get("id").(string)
	mapped := m.call("connections/mappings", obj("tenantId", tenantID, "connectionId", connection.id, "groupId", engineering, "roleIds", list(readersID)), "", nil, "")
	if mapped.status != 200 || mapped.data() != nil {
		t.Fatalf("mappings: %d %s", mapped.status, show(mapped.body))
	}
	regrouped := m.call("connections/groups", obj("tenantId", tenantID, "connectionId", connection.id), "", nil, "").data().([]any)
	sameJSON(t, member(regrouped[1], "roleIds"), list(readersID))
	identityID := get(t, m.store, "scimUsers", user).Get("identityId")
	effective := func() []any {
		out, err := m.iam.API.Identities.ListBindings(m.ctx, m.owner, server.Input[apitypes.IdentitiesListBindingsInput](obj("tenantId", tenantID, "identityId", identityID)))
		requirePorted(t, err)
		return out.Value.([]any)
	}
	bindings := effective()
	if len(bindings) != 1 || member(bindings[0], "roleId") != readersID || member(member(bindings[0], "via"), "groupId") != localGroupID {
		t.Fatalf("bindings: %s", show(bindings))
	}
	if got := m.call("connections/mappings", obj("tenantId", tenantID, "connectionId", connection.id, "groupId", engineering, "roleIds", "everything"), "", nil, ""); got.status != 400 {
		t.Fatalf("roleIds string: %d", got.status)
	}

	rotated := m.call("connections/rotate", obj("tenantId", tenantID, "connectionId", connection.id, "expiresIn", 3600), "", nil, "")
	if rotated.status != 200 {
		t.Fatalf("rotate: %d %s", rotated.status, show(rotated.body))
	}
	token := member(rotated.data(), "token").(string)
	if token == connection.token {
		t.Fatal("token unchanged")
	}
	if got := m.scim(connection, "Users", "", nil); got.status != 401 {
		t.Fatalf("old token: %d", got.status)
	}
	renewed := connection
	renewed.token = token
	if got := m.scim(renewed, "Users", "", nil); got.status != 200 {
		t.Fatalf("new token: %d", got.status)
	}

	revoked := m.call("connections/revoke", obj("tenantId", tenantID, "connectionId", connection.id), "", nil, "")
	if revoked.status != 200 || revoked.data() != nil {
		t.Fatalf("revoke: %d %s", revoked.status, show(revoked.body))
	}
	if got := m.scim(renewed, "Users", "", nil); got.status != 401 {
		t.Fatalf("revoked token: %d", got.status)
	}
	if member(m.call("connections/list", obj("tenantId", tenantID), "", nil, "").data().([]any)[0], "revoked") != true {
		t.Fatal("not revoked")
	}
	if len(effective()) != 0 {
		t.Fatal("bindings survived the revocation")
	}
}

func TestAdminRefusesCrossSiteMalformedUnknownAndUnauthorizedRequests(t *testing.T) {
	m := newMounted(t)
	tenantID := m.tenantID
	request := httptest.NewRequest("POST", fixtureOrigin+"/api/iam/scim-admin/connections/list", jsonBody(obj("tenantId", tenantID)))
	request.Header.Set("content-type", "application/json")
	request.Header.Set("authorization", "Bearer "+m.owner.Token)
	missingHeader := decodeServer(t, m.iam.Handle(request))
	if missingHeader.status != 403 || missingHeader.get("error", "code") != "CSRF_REJECTED" {
		t.Fatalf("missing header: %d %s", missingHeader.status, show(missingHeader.body))
	}
	if got := m.call("connections/list", obj("tenantId", tenantID), "", map[string]string{"content-type": "text/plain"}, ""); got.errorCode() != "CSRF_REJECTED" {
		t.Fatalf("text/plain: %s", show(got.body))
	}
	if got := m.call("connections/create", obj("tenantId", tenantID, "name", "Evil"), "", map[string]string{"origin": "https://evil.test"}, ""); got.status != 403 || got.errorCode() != "CSRF_REJECTED" {
		t.Fatalf("cross-site: %d %s", got.status, show(got.body))
	}
	if got := m.call("connections/list", obj("tenantId", tenantID), "", map[string]string{"origin": fixtureOrigin}, ""); got.status != 200 {
		t.Fatalf("same origin: %d %s", got.status, show(got.body))
	}
	if got := m.call("connections/list", nil, "", nil, "GET"); got.status != 405 || got.errorCode() != "METHOD_NOT_ALLOWED" {
		t.Fatalf("GET: %d %s", got.status, show(got.body))
	}
	for _, route := range []string{"connections/nope", "constructor", "connections"} {
		if got := m.call(route, obj("tenantId", tenantID), "", nil, ""); got.status != 404 || got.cacheControl != "no-store" || got.errorCode() != "NOT_FOUND" {
			t.Fatalf("%s: %d %s", route, got.status, show(got.body))
		}
	}
	for _, body := range []any{"[1]", "{nope", obj()} {
		if got := m.call("connections/list", body, "", nil, ""); got.status != 400 {
			t.Fatalf("%v: %d", body, got.status)
		}
	}
	if got := m.call("connections/create", obj("tenantId", tenantID, "name", strings.Repeat("x", 70*1024)), "", nil, ""); got.status != 413 {
		t.Fatalf("oversized: %d", got.status)
	}
	if got := m.call("connections/groups", obj("tenantId", tenantID, "connectionId", "missing"), "", nil, ""); got.status != 404 {
		t.Fatalf("missing connection: %d", got.status)
	}

	// A member without SCIM permissions is denied, and nothing was created on their behalf.
	m.member("alice")
	alice := m.signIn("alice@acme.test")
	for _, attempt := range []struct {
		route string
		body  *core.Object
	}{
		{"connections/list", obj("tenantId", tenantID)},
		{"connections/create", obj("tenantId", tenantID, "name", "Shadow")},
	} {
		if got := m.call(attempt.route, attempt.body, alice.Token, nil, ""); got.status != 403 {
			t.Fatalf("%s: %d %s", attempt.route, got.status, show(got.body))
		}
	}
	if rows := m.call("connections/list", obj("tenantId", tenantID), "", nil, "").data().([]any); len(rows) != 0 {
		t.Fatalf("created on a member's behalf: %s", show(rows))
	}
}

func TestAdminHidesUnexpectedFailuresAndValidatesItsPaths(t *testing.T) {
	m := newMounted(t)
	config := hostConfig(m.iam)
	config.Authorize = func(context.Context, core.CredentialInput, string, core.ResourceRef) error {
		return errors.New("database exploded")
	}
	failing := must(NewService(config))
	request := httptest.NewRequest("POST", fixtureOrigin+"/scim/admin/connections/list", jsonBody(obj("tenantId", m.tenantID)))
	request.Header.Set("content-type", "application/json")
	request.Header.Set("x-better-iam", "1")
	response := decode(t, failing.Handle(request))
	if response.status != 500 || response.get("error", "code") != "INTERNAL_ERROR" || strings.Contains(show(response.body), "exploded") {
		t.Fatalf("failure: %d %s", response.status, show(response.body))
	}
	if failing.Handle(httptest.NewRequest("GET", fixtureOrigin+"/elsewhere", nil)) != nil {
		t.Fatal("answered outside its paths")
	}
	for _, paths := range [][2]string{
		{"/scim/v2", "/scim/v2"},
		{"/scim/v2", "/scim/v2/admin"},
		{"/scim/admin/v2", "/scim/admin"},
		{"/scim/v2", "scim/admin"},
	} {
		config := hostConfig(m.iam)
		config.BasePath, config.AdminBasePath = paths[0], paths[1]
		_, err := NewService(config)
		expectCode(t, err, "configuration", 0)
	}
	config = hostConfig(m.iam)
	config.BasePath, config.AdminBasePath = "/scim", "/scim-admin"
	if service := must(NewService(config)); service.AdminBasePath != "/scim-admin" {
		t.Fatalf("adminBasePath: %s", service.AdminBasePath)
	}
}
