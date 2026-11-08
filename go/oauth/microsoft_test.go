package oauth

// Port of tests/oauth-microsoft.test.ts.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

const (
	contoso  = "72f988bf-86f1-41af-91ab-2d7cd011db47"
	fabrikam = "0b6c1f2a-5d3e-4c4f-9a1b-2c3d4e5f6a7b"
)

type entraIssue struct {
	tid     string
	iss     string
	xmsEdov *bool
}

type entraFixture struct {
	store  core.IamStore
	origin string
	mu     sync.Mutex
	issued entraIssue
	nonce  string
}

func newEntraFixture(t *testing.T) *entraFixture {
	t.Helper()
	store := newTestStore(t)
	insert(t, store, "tenants", core.NewObject("id", "a", "tenantId", "a", "name", "A", "type", "organization", "parentId", nil, "status", "active", "createdAt", wallNow()))
	f := &entraFixture{store: store, issued: entraIssue{tid: contoso}}
	signing, public := testRSAKey()
	signing.Set("kid", "entra")
	signing.Delete("use")
	public.Set("kid", "entra")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		directory := strings.Split(r.URL.Path, "/")[1]
		switch {
		case strings.HasSuffix(r.URL.Path, "/v2.0/.well-known/openid-configuration"):
			issuerDirectory := directory
			if directory == "organizations" || directory == "common" {
				issuerDirectory = "{tenantid}"
			}
			_, _ = w.Write([]byte(stringify(core.NewObject("issuer", f.origin+"/"+issuerDirectory+"/v2.0",
				"authorization_endpoint", f.origin+"/"+directory+"/oauth2/v2.0/authorize", "token_endpoint", f.origin+"/"+directory+"/oauth2/v2.0/token",
				"jwks_uri", f.origin+"/"+directory+"/discovery/v2.0/keys", "response_types_supported", []any{"code"},
				"id_token_signing_alg_values_supported", []any{"RS256"}))))
		case strings.HasSuffix(r.URL.Path, "/discovery/v2.0/keys"):
			_, _ = w.Write([]byte(stringify(core.NewObject("keys", []any{public}))))
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			_, _ = io.ReadAll(r.Body)
			f.mu.Lock()
			issued, nonce := f.issued, f.nonce
			f.mu.Unlock()
			claims := core.NewObject("nonce", nonce, "tid", issued.tid, "email", "ada@contoso.test", "name", "Ada")
			if issued.xmsEdov != nil {
				claims.Set("xms_edov", *issued.xmsEdov)
			}
			iss := issued.iss
			if iss == "" {
				iss = f.origin + "/" + issued.tid + "/v2.0"
			}
			now := epoch(wallNow())
			claims.Set("iss", iss)
			claims.Set("aud", "entra-client")
			claims.Set("sub", "pairwise-"+issued.tid)
			claims.Set("iat", now)
			claims.Set("exp", now+300)
			idToken := signJWT(t, signing, "RS256", core.NewObject("kid", "entra"), claims)
			_, _ = w.Write([]byte(stringify(core.NewObject("access_token", "at", "token_type", "Bearer", "id_token", idToken, "expires_in", 300))))
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte("{}"))
		}
	}))
	t.Cleanup(server.Close)
	f.origin = server.URL
	return f
}

func (f *entraFixture) setIssued(issued entraIssue) {
	f.mu.Lock()
	f.issued = issued
	f.mu.Unlock()
}

func (f *entraFixture) login(t *testing.T, change func(connection *OAuthLoginConnection)) (*OAuthLoginService, *[]*core.Object, error) {
	identities := &[]*core.Object{}
	connection := OAuthLoginConnection{ID: "entra", TenantID: "a", Kind: "microsoft", Issuer: f.origin, ClientID: "entra-client",
		ClientSecret: "entra-secret", RedirectURI: f.origin + "/callback", AllowedMicrosoftTenants: []string{strings.ToUpper(contoso)}}
	if change != nil {
		change(&connection)
	}
	service, err := CreateOAuthLogin(OAuthLoginConfig{Store: f.store, AllowInsecureLocalhost: true, Connections: []OAuthLoginConnection{connection},
		CompleteAuthentication: func(_ context.Context, identity FederatedIdentity) (any, error) {
			*identities = append(*identities, identity)
			return core.NewObject("ok", true), nil
		}})
	return service, identities, err
}

func (f *entraFixture) run(t *testing.T, service *OAuthLoginService) (*url.URL, func() (any, error)) {
	t.Helper()
	ctx := context.Background()
	begin, err := service.Begin(ctx, "entra", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(begin.URL)
	f.mu.Lock()
	f.nonce = parsed.Query().Get("nonce")
	f.mu.Unlock()
	return parsed, func() (any, error) {
		return service.Callback(ctx, "entra", f.origin+"/callback?code=c&state="+url.QueryEscape(begin.State), begin.Binding)
	}
}

func TestMicrosoftAllowedDirectories(t *testing.T) {
	f := newEntraFixture(t)
	service, identities, err := f.login(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	flowURL, result := f.run(t, service)
	if flowURL.Scheme+"://"+flowURL.Host+flowURL.Path != f.origin+"/organizations/oauth2/v2.0/authorize" || flowURL.Query().Get("scope") != "openid email profile" {
		t.Fatalf("unexpected authorization URL %s", flowURL)
	}
	if value, err := result(); err != nil || stringify(value) != `{"ok":true}` {
		t.Fatalf("unexpected result %v %v", value, err)
	}
	first := (*identities)[0]
	if str(first, "tenantId") != "a" || str(first, "providerId") != "entra" || str(first, "issuer") != f.origin+"/"+contoso+"/v2.0" ||
		str(first, "subject") != "pairwise-"+contoso || str(first, "email") != "ada@contoso.test" || first.Get("emailVerified") != false {
		t.Fatalf("unexpected identity %s", stringify(first))
	}
	verified := true
	f.setIssued(entraIssue{tid: contoso, xmsEdov: &verified})
	_, result = f.run(t, service)
	if _, err := result(); err != nil {
		t.Fatal(err)
	}
	if (*identities)[1].Get("emailVerified") != true {
		t.Fatalf("expected a verified email, got %s", stringify((*identities)[1]))
	}
}

func TestMicrosoftRefusesForeignDirectories(t *testing.T) {
	f := newEntraFixture(t)
	service, identities, err := f.login(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.setIssued(entraIssue{tid: fabrikam})
	_, result := f.run(t, service)
	_, err = result()
	expectIamError(t, err, 403, "OAUTH_TENANT")
	f.setIssued(entraIssue{tid: contoso, iss: f.origin + "/" + fabrikam + "/v2.0"})
	_, result = f.run(t, service)
	if _, err := result(); err == nil {
		t.Fatal("expected an issuer mismatch to fail")
	}
	if len(*identities) != 0 {
		t.Fatalf("expected no identities, got %d", len(*identities))
	}
}

func TestMicrosoftSignInHints(t *testing.T) {
	f := newEntraFixture(t)
	service, _, err := f.login(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	hint, domain, prompt := "ada@contoso.test", "contoso.test", "select_account"
	begun, err := service.Begin(ctx, "entra", nil, &LoginHints{LoginHint: &hint, DomainHint: &domain, Prompt: &prompt})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(begun.URL)
	if parsed.Query().Get("login_hint") != hint || parsed.Query().Get("domain_hint") != domain || parsed.Query().Get("prompt") != prompt {
		t.Fatalf("unexpected hints %s", begun.URL)
	}
	redirect := service.Handler(ctx, httptest.NewRequest("GET", f.origin+"/oauth/login/entra?login_hint=bob%40contoso.test&prompt=login", nil))
	if redirect == nil || redirect.Status != 302 {
		t.Fatalf("expected a redirect, got %+v", redirect)
	}
	location, _ := url.Parse(redirect.Header.Get("location"))
	if location.Query().Get("login_hint") != "bob@contoso.test" || location.Query().Get("prompt") != "login" {
		t.Fatalf("unexpected location %s", location)
	}
	bad := "<script>"
	_, err = service.Begin(ctx, "entra", nil, &LoginHints{LoginHint: &bad})
	expectIamError(t, err, 0, "INVALID_INPUT")
	always := "always"
	_, err = service.Begin(ctx, "entra", nil, &LoginHints{Prompt: &always})
	expectIamError(t, err, 0, "INVALID_INPUT")
	invalid := service.Handler(ctx, httptest.NewRequest("GET", f.origin+"/oauth/login/entra?domain_hint=not%20a%20domain", nil))
	if invalid == nil || invalid.Status != 400 {
		t.Fatalf("expected 400, got %+v", invalid)
	}
}

func TestMicrosoftSingleTenantAndConfiguration(t *testing.T) {
	f := newEntraFixture(t)
	service, identities, err := f.login(t, func(connection *OAuthLoginConnection) {
		connection.MicrosoftTenant = contoso
		connection.AllowedMicrosoftTenants = nil
	})
	if err != nil {
		t.Fatal(err)
	}
	flowURL, result := f.run(t, service)
	if flowURL.Path != "/"+contoso+"/oauth2/v2.0/authorize" {
		t.Fatalf("unexpected path %s", flowURL.Path)
	}
	if value, err := result(); err != nil || stringify(value) != `{"ok":true}` {
		t.Fatalf("unexpected result %v %v", value, err)
	}
	if len(*identities) != 1 || str((*identities)[0], "issuer") != f.origin+"/"+contoso+"/v2.0" {
		t.Fatalf("unexpected identities %v", *identities)
	}
	f.setIssued(entraIssue{tid: fabrikam})
	_, result = f.run(t, service)
	if _, err := result(); err == nil {
		t.Fatal("expected another directory to fail")
	}
	if len(*identities) != 1 {
		t.Fatalf("expected one identity, got %d", len(*identities))
	}
	if _, _, err := f.login(t, func(connection *OAuthLoginConnection) { connection.AllowedMicrosoftTenants = nil }); err == nil || !strings.Contains(err.Error(), "allowedMicrosoftTenants") {
		t.Fatalf("expected an allowedMicrosoftTenants refusal, got %v", err)
	}
	if _, _, err := f.login(t, func(connection *OAuthLoginConnection) { connection.MicrosoftTenant = "../evil" }); err == nil || !strings.Contains(err.Error(), "microsoftTenant") {
		t.Fatalf("expected a microsoftTenant refusal, got %v", err)
	}
}
