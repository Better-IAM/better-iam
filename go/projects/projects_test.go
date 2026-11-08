package projects_test

// Port of tests/projects.test.ts. The fixture drives the server through the typed Go client over the server's HTTP
// handler, and calls the plugin with iam.CallPlugin as the TypeScript test does.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/Better-IAM/better-iam/go/adapters/sqlite"
	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/client"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/projects"
	"github.com/Better-IAM/better-iam/go/server"
)

const baseURL = "http://localhost:3000"

type fixture struct {
	t          *testing.T
	ctx        context.Context
	iam        *server.BetterIam
	database   core.IamStore
	rootTenant string
	rootID     string
	credential core.CredentialInput
	mu         sync.Mutex
	inbox      []auth.DeliveryMessage
}

type tenant struct {
	id         string
	ownerID    string
	credential core.CredentialInput
}

// handlerFetch sends a client request to the server's fetch-style handler (iam.handler(new Request(...))).
func handlerFetch(iam *server.BetterIam) func(request *http.Request) (*http.Response, error) {
	return func(request *http.Request) (*http.Response, error) {
		response := iam.Handle(request)
		return &http.Response{StatusCode: response.Status, Header: response.Header, Body: io.NopCloser(bytes.NewReader(response.Body))}, nil
	}
}

func (f *fixture) client(credential core.CredentialInput) *client.Client {
	f.t.Helper()
	c, err := client.New(client.Options{BaseURL: baseURL, Token: credential.Token, Fetch: handlerFetch(f.iam)})
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	linked := "linked"
	database, err := sqlite.New(sqlite.Options{Filename: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	f := &fixture{t: t, ctx: context.Background(), database: database}
	iam, err := server.New(&server.BetterIamOptions{
		Database: database,
		Secret:   "test-secret-with-at-least-32-characters",
		BaseURL:  baseURL,
		Authentication: &auth.Options{SendEmail: func(_ context.Context, message auth.DeliveryMessage) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.inbox = append(f.inbox, message)
			return nil
		}},
		Onboarding: &server.OnboardingOptions{Mode: &linked},
		Plugins:    []*core.IamPlugin{projects.NewPlugin()},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(iam.Close)
	f.iam = iam
	if err := iam.Initialize(f.ctx); err != nil {
		t.Fatal(err)
	}
	root, err := iam.Bootstrap(f.ctx, core.NewObject("email", "root@example.test", "name", "Root", "password", "a strong root test password"))
	if err != nil {
		t.Fatal(err)
	}
	f.rootTenant = root.Get("tenant").(*core.Object).Get("id").(string)
	f.rootID = root.Get("identity").(*core.Object).Get("id").(string)
	public := f.client(core.CredentialInput{})
	challenge, err := public.Auth.SignIn(f.ctx, apitypes.AuthSignInInput{TenantID: f.rootTenant, Email: "root@example.test", Password: "a strong root test password"})
	if err != nil {
		t.Fatal(err)
	}
	if challenge.MfaRequired == nil {
		t.Fatal("Root must require MFA")
	}
	restricted := &client.MfaChallenge{TenantID: f.rootTenant, Challenge: challenge.MfaRequired.Challenge}
	enrollment, err := public.Auth.BeginMfa(f.ctx, restricted)
	if err != nil {
		t.Fatal(err)
	}
	code, err := auth.GenerateTotp(enrollment.Secret, core.NowMillis())
	if err != nil {
		t.Fatal(err)
	}
	session, err := public.Auth.ConfirmMfa(f.ctx, client.ConfirmMfaInput{Credential: restricted, Code: code})
	if err != nil {
		t.Fatal(err)
	}
	f.credential = core.CredentialInput{Token: session.Token}
	return f
}

func (f *fixture) createTenant(name, parent, kind string) tenant {
	f.t.Helper()
	if parent == "" {
		parent = f.rootTenant
	}
	if kind == "" {
		kind = "organization"
	}
	created, err := f.client(f.credential).Tenants.Create(f.ctx, apitypes.TenantsCreateInput{
		ParentID: parent, Name: name, Type: kind, OwnerEmail: name + "@example.test",
	})
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.iam.Auth.DispatchOutbox(f.ctx, 0); err != nil {
		f.t.Fatal(err)
	}
	var token string
	f.mu.Lock()
	for _, message := range f.inbox {
		if message.TenantID == created.Tenant.ID && message.Template == "owner-invitation" {
			token = message.Payload["token"]
		}
	}
	f.mu.Unlock()
	if token == "" {
		f.t.Fatalf("no owner invitation for %s", name)
	}
	owner, err := f.client(core.CredentialInput{}).Tenants.AcceptInvitation(f.ctx, apitypes.TenantsAcceptInvitationInput{
		TenantID: created.Tenant.ID, Token: token, Name: name + " owner", Password: "a strong tenant owner password",
	})
	if err != nil {
		f.t.Fatal(err)
	}
	session := owner.Token
	if session == nil {
		f.t.Fatal("Unexpected owner MFA")
	}
	return tenant{id: created.Tenant.ID, ownerID: session.Identity.ID, credential: core.CredentialInput{Token: session.Token}}
}

func (f *fixture) call(path string, who core.CredentialInput, tenantID string, input *core.Object) (any, error) {
	if input == nil {
		input = core.NewObject()
	}
	return f.iam.CallPlugin(f.ctx, who, server.PluginCall{PluginID: "projects", Path: path, TenantID: tenantID, Input: input})
}

func (f *fixture) project(path string, who core.CredentialInput, tenantID string, input *core.Object) *core.Object {
	f.t.Helper()
	result, err := f.call(path, who, tenantID, input)
	if err != nil {
		f.t.Fatalf("%s: %v", path, err)
	}
	project, ok := result.(*core.Object)
	if !ok {
		f.t.Fatalf("%s answered %T", path, result)
	}
	return project
}

func (f *fixture) list(who core.CredentialInput, tenantID string, input *core.Object) []*core.Object {
	f.t.Helper()
	result, err := f.call("list", who, tenantID, input)
	if err != nil {
		f.t.Fatalf("list: %v", err)
	}
	listed, ok := result.([]*core.Object)
	if !ok {
		f.t.Fatalf("list answered %T", result)
	}
	return listed
}

func expectCode(t *testing.T, err error, code string) {
	t.Helper()
	var known *core.IamError
	if !errors.As(err, &known) || known.Code != code {
		t.Fatalf("expected %s, got %v", code, err)
	}
}

func ids(records []*core.Object) []string {
	out := make([]string, 0, len(records))
	for _, record := range records {
		out = append(out, record.Get("id").(string))
	}
	return out
}

func equal(a, b []string) bool {
	return strings.Join(a, "\x00") == strings.Join(b, "\x00")
}

func TestProjectsManagesTheProjectLifecycleInTheRootTenantAndOrganizationTenants(t *testing.T) {
	f := newFixture(t)
	platform := f.project("create", f.credential, f.rootTenant, core.NewObject("name", "Platform", "description", "Deployment-level project"))
	if platform.Get("name") != "Platform" || platform.Get("status") != "active" || platform.Get("tenantId") != f.rootTenant ||
		platform.Get("createdBy") != f.rootID || platform.Get("description") != "Deployment-level project" {
		t.Fatalf("created %s", core.MustStringify(platform))
	}
	if keys := strings.Join(platform.Keys(), ","); keys != "id,tenantId,name,description,status,createdBy,createdAt,updatedAt" {
		t.Fatalf("record members %s", keys)
	}
	_, err := f.call("create", f.credential, f.rootTenant, core.NewObject("name", "Platform"))
	expectCode(t, err, "CONFLICT")
	_, err = f.call("create", f.credential, f.rootTenant, core.NewObject("name", "   "))
	expectCode(t, err, "INVALID_INPUT")
	_, err = f.call("create", f.credential, f.rootTenant, core.NewObject("name", strings.Repeat("x", 101)))
	expectCode(t, err, "INVALID_INPUT")
	_, err = f.call("create", f.credential, f.rootTenant, core.NewObject("name", "Fields", "owner", "forged"))
	expectCode(t, err, "INVALID_INPUT")
	a := f.createTenant("acme", "", "")
	_, err = f.call("create", a.credential, a.id, core.NewObject("tenantId", f.rootTenant, "name", "Forged scope"))
	expectCode(t, err, "INVALID_INPUT")
	// The same name is available in another tenant.
	first := f.project("create", a.credential, a.id, core.NewObject("name", "Platform"))
	if first.Get("tenantId") != a.id || first.Get("createdBy") != a.ownerID || first.Get("status") != "active" {
		t.Fatalf("created %s", core.MustStringify(first))
	}
	_, err = f.call("update", a.credential, a.id, core.NewObject("projectId", first.Get("id")))
	expectCode(t, err, "INVALID_INPUT")
	if renamed := f.project("update", a.credential, a.id, core.NewObject("projectId", first.Get("id"), "name", "Platform Core")); renamed.Get("name") != "Platform Core" {
		t.Fatalf("renamed %s", core.MustStringify(renamed))
	}
	if described := f.project("update", a.credential, a.id, core.NewObject("projectId", first.Get("id"), "description", "Owned by acme")); described.Get("description") != "Owned by acme" {
		t.Fatalf("described %s", core.MustStringify(described))
	}
	if cleared := f.project("update", a.credential, a.id, core.NewObject("projectId", first.Get("id"), "description", "")); cleared.Has("description") {
		t.Fatalf("cleared %s", core.MustStringify(cleared))
	}
	second := f.project("create", a.credential, a.id, core.NewObject("name", "Second"))
	_, err = f.call("update", a.credential, a.id, core.NewObject("projectId", second.Get("id"), "name", "Platform Core"))
	expectCode(t, err, "CONFLICT")
	if archived := f.project("archive", a.credential, a.id, core.NewObject("projectId", second.Get("id"))); archived.Get("status") != "archived" {
		t.Fatalf("archived %s", core.MustStringify(archived))
	}
	_, err = f.call("archive", a.credential, a.id, core.NewObject("projectId", second.Get("id")))
	expectCode(t, err, "INVALID_TRANSITION")
	if got := ids(f.list(a.credential, a.id, core.NewObject("status", "archived"))); !equal(got, []string{second.Get("id").(string)}) {
		t.Fatalf("archived list %v", got)
	}
	if got := ids(f.list(a.credential, a.id, core.NewObject("status", "active"))); !equal(got, []string{first.Get("id").(string)}) {
		t.Fatalf("active list %v", got)
	}
	var names []string
	for _, project := range f.list(a.credential, a.id, nil) {
		names = append(names, project.Get("name").(string))
	}
	sort.Strings(names)
	if !equal(names, []string{"Platform Core", "Second"}) {
		t.Fatalf("names %v", names)
	}
	if restored := f.project("restore", a.credential, a.id, core.NewObject("projectId", second.Get("id"))); restored.Get("status") != "active" {
		t.Fatalf("restored %s", core.MustStringify(restored))
	}
	_, err = f.call("restore", a.credential, a.id, core.NewObject("projectId", second.Get("id")))
	expectCode(t, err, "INVALID_TRANSITION")
	if got := f.project("get", a.credential, a.id, core.NewObject("projectId", second.Get("id"))); got.Get("name") != "Second" {
		t.Fatalf("get %s", core.MustStringify(got))
	}
	_, err = f.call("get", a.credential, a.id, core.NewObject("projectId", platform.Get("id")))
	expectCode(t, err, "NOT_FOUND")
}

func TestProjectsIsolatesTenantsAndEnforcesPoliciesForProjectAccess(t *testing.T) {
	f := newFixture(t)
	a, b := f.createTenant("alpha", "", ""), f.createTenant("beta", "", "")
	project := f.project("create", a.credential, a.id, core.NewObject("name", "Alpha project"))
	_, err := f.call("create", b.credential, a.id, core.NewObject("name", "Intrusion"))
	expectCode(t, err, "ACCESS_DENIED")
	_, err = f.call("list", b.credential, a.id, nil)
	expectCode(t, err, "ACCESS_DENIED")
	_, err = f.call("get", b.credential, a.id, core.NewObject("projectId", project.Get("id")))
	expectCode(t, err, "ACCESS_DENIED")
	if listed := f.list(b.credential, b.id, nil); len(listed) != 0 {
		t.Fatalf("beta sees %v", ids(listed))
	}
	owner := f.client(a.credential)
	password := "a strong reader test password"
	reader, err := owner.Identities.Create(f.ctx, apitypes.IdentitiesCreateInput{TenantID: a.id, Email: "reader@example.test", Name: "Reader", Password: &password})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := owner.Policies.Create(f.ctx, apitypes.PoliciesCreateInput{TenantID: a.id, Name: "Project reader", Document: core.PolicyDocument{
		Version: 1, Statements: []core.PolicyStatement{{Effect: "allow", Actions: []string{"projects:read"}, Resources: []string{"iam/*"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	role, err := owner.Roles.Create(f.ctx, apitypes.RolesCreateInput{TenantID: a.id, Name: "Reader", PolicyIDs: []string{policy.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Bindings.Create(f.ctx, apitypes.BindingsCreateInput{TenantID: a.id, RoleID: role.ID, SubjectType: "identity", SubjectID: reader.ID}); err != nil {
		t.Fatal(err)
	}
	signed, err := f.client(core.CredentialInput{}).Auth.SignIn(f.ctx, apitypes.AuthSignInInput{TenantID: a.id, Email: "reader@example.test", Password: password})
	if err != nil {
		t.Fatal(err)
	}
	if signed.SessionResult == nil {
		t.Fatal("Unexpected MFA")
	}
	readerCredential := core.CredentialInput{Token: signed.SessionResult.Token}
	if got := f.project("get", readerCredential, a.id, core.NewObject("projectId", project.Get("id"))); got.Get("name") != "Alpha project" {
		t.Fatalf("reader get %s", core.MustStringify(got))
	}
	_, err = f.call("create", readerCredential, a.id, core.NewObject("name", "Nope"))
	expectCode(t, err, "ACCESS_DENIED")
	if got := ids(f.list(f.credential, a.id, nil)); !equal(got, []string{project.Get("id").(string)}) {
		t.Fatalf("root list %v", got)
	}
}

func TestProjectsAppliesAncestorTenantBoundariesToPluginActions(t *testing.T) {
	f := newFixture(t)
	a := f.createTenant("bounded", "", "")
	project := f.project("create", a.credential, a.id, core.NewObject("name", "Bounded project"))
	if _, err := f.client(f.credential).Tenants.SetBoundary(f.ctx, apitypes.TenantsSetBoundaryInput{TenantID: a.id, Boundary: core.PolicyDocument{
		Version: 1, Statements: []core.PolicyStatement{{Effect: "allow", Actions: []string{"iam:*"}, Resources: []string{"*"}}},
	}}); err != nil {
		t.Fatal(err)
	}
	_, err := f.call("create", a.credential, a.id, core.NewObject("name", "Blocked"))
	expectCode(t, err, "ACCESS_DENIED")
	_, err = f.call("list", a.credential, a.id, nil)
	expectCode(t, err, "ACCESS_DENIED")
	_, err = f.call("archive", a.credential, a.id, core.NewObject("projectId", project.Get("id")))
	expectCode(t, err, "ACCESS_DENIED")
	if got := ids(f.list(f.credential, a.id, nil)); !equal(got, []string{project.Get("id").(string)}) {
		t.Fatalf("root list %v", got)
	}
}

func TestProjectsRemovesPurgedTenantsProjectRecordsThroughThePurgeCallback(t *testing.T) {
	f := newFixture(t)
	a, b := f.createTenant("alpha", "", ""), f.createTenant("beta", "", "")
	inA := f.project("create", a.credential, a.id, core.NewObject("name", "Alpha one"))
	child := f.createTenant("alpha-web", a.id, "project")
	inChild := f.project("create", child.credential, child.id, core.NewObject("name", "Alpha web"))
	inB := f.project("create", b.credential, b.id, core.NewObject("name", "Beta one"))
	if _, err := f.client(f.credential).Tenants.SetStatus(f.ctx, apitypes.TenantsSetStatusInput{TenantID: a.id, Status: apitypes.TenantsSetStatusInputStatusDeleted}); err != nil {
		t.Fatal(err)
	}
	purge, err := f.iam.PurgeDeleted(f.ctx, core.NewObject("retentionMs", 0))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{a.id, child.id}
	sort.Strings(want)
	var purged []string
	for _, id := range purge.Get("purgedTenants").([]any) {
		purged = append(purged, id.(string))
	}
	if !equal(purged, want) {
		t.Fatalf("purged %v, want %v", purged, want)
	}
	find := func(collection string, filter *core.Object) []*core.Object {
		records, err := f.database.Find(f.ctx, collection, filter, nil)
		if err != nil {
			t.Fatal(err)
		}
		return records
	}
	if left := find("projects", core.NewObject("tenantId", a.id)); len(left) != 0 {
		t.Fatalf("alpha projects left: %v", ids(left))
	}
	if left := find("projects", core.NewObject("tenantId", child.id)); len(left) != 0 {
		t.Fatalf("child projects left: %v", ids(left))
	}
	if got := ids(find("projects", core.NewObject("tenantId", b.id))); !equal(got, []string{inB.Get("id").(string)}) {
		t.Fatalf("beta projects %v", got)
	}
	if inA.Get("id") == inChild.Get("id") {
		t.Fatal("project ids collide")
	}
	if audits := find("audit", core.NewObject("tenantId", a.id, "action", "tenants:purge")); len(audits) != 1 {
		t.Fatalf("purge audits %d", len(audits))
	}
}

func TestProjectsServesThePluginOverHTTPWithTheSameAuthorizationBoundary(t *testing.T) {
	f := newFixture(t)
	a := f.createTenant("http", "", "")
	call := func(path string, body string, headers map[string]string) *server.Response {
		request := httptest.NewRequest(http.MethodPost, baseURL+"/api/iam/plugins/projects/"+path, strings.NewReader(body))
		request.Header.Set("content-type", "application/json")
		request.Header.Set("x-better-iam", "1")
		request.Header.Set("authorization", "Bearer "+a.credential.Token)
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		return f.iam.Handle(request)
	}
	data := func(response *server.Response) any {
		parsed, err := core.ParseJSON(response.Body)
		if err != nil {
			t.Fatalf("invalid JSON %s", response.Body)
		}
		return parsed.(*core.Object).Get("data")
	}
	response := call("create", `{"tenantId":"`+a.id+`","name":"HTTP project"}`, nil)
	if response.Status != 200 {
		t.Fatalf("create: %d %s", response.Status, response.Body)
	}
	created := data(response).(*core.Object)
	if created.Get("name") != "HTTP project" || created.Get("tenantId") != a.id || created.Get("createdBy") != a.ownerID || created.Get("status") != "active" {
		t.Fatalf("created %s", core.MustStringify(created))
	}
	listed := data(call("list", `{"tenantId":"`+a.id+`"}`, nil)).([]any)
	if len(listed) != 1 || listed[0].(*core.Object).Get("id") != created.Get("id") {
		t.Fatalf("listed %v", listed)
	}
	if status := call("get", `{"tenantId":"`+a.id+`","projectId":"`+created.Get("id").(string)+`"}`, nil).Status; status != 200 {
		t.Fatalf("get: %d", status)
	}
	if status := call("list", `{"tenantId":"`+a.id+`"}`, map[string]string{"x-better-iam": "0"}).Status; status != 403 {
		t.Fatalf("list without the CSRF header: %d", status)
	}
	other := f.createTenant("other", "", "")
	if status := call("list", `{"tenantId":"`+other.id+`"}`, nil).Status; status != 403 {
		t.Fatalf("list in another tenant: %d", status)
	}
	if status := call("destroy", `{"tenantId":"`+a.id+`","projectId":"`+created.Get("id").(string)+`"}`, nil).Status; status != 404 {
		t.Fatalf("unknown endpoint: %d", status)
	}
	if status := call("create", `{"tenantId":"`+a.id+`","name":"No owner"}`, map[string]string{"authorization": ""}).Status; status != 401 {
		t.Fatalf("create without a credential: %d", status)
	}
	// The typed client's plugin transport reaches the same endpoints.
	c := f.client(a.credential)
	projectsList, err := client.Call[[]projects.Project](f.ctx, c, "plugins/projects/list", core.NewObject("tenantId", a.id))
	if err != nil {
		t.Fatal(err)
	}
	if len(projectsList) != 1 || projectsList[0].ID != created.Get("id") || projectsList[0].Status != "active" {
		t.Fatalf("client list %+v", projectsList)
	}
	_, err = c.Request(f.ctx, "plugins/projects/list", core.NewObject("tenantId", other.id))
	var refused *client.IamClientError
	if !errors.As(err, &refused) || refused.Code != "ACCESS_DENIED" || refused.Status != 403 {
		t.Fatalf("client list in another tenant: %v", err)
	}
}
