package oauth

// Port of tests/oauth-registration.test.ts.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const mcpAPI = "https://mcp.example.test/mcp"

type registrationFixture struct {
	*oauthFixture
	publicClient func() *core.Object
}

func newRegistrationFixture(t *testing.T, configure func(config *OAuthProviderConfig)) *registrationFixture {
	t.Helper()
	store := newTestStore(t)
	now := wallNow()
	for _, id := range []string{"a", "b"} {
		insert(t, store, "tenants", core.NewObject("id", id, "tenantId", id, "name", id, "type", "organization", "parentId", nil, "status", "active", "createdAt", now))
	}
	insert(t, store, "identities", core.NewObject("id", "user-a", "tenantId", "a", "name", "Ada", "kind", "user", "email", "ada@example.test",
		"emailVerified", true, "status", "active", "rootAdmin", false, "owner", false, "createdAt", now))
	server := newProviderServer(t)
	origin := server.URL
	identity, _ := store.Get(context.Background(), "identities", "user-a")
	session := core.NewObject("id", "session-a", "tenantId", "a", "identityId", "user-a", "kind", "user", "tokenHash", "irrelevant",
		"createdAt", now, "authenticatedAt", now, "lastSeenAt", now, "expiresAt", now+100000, "mfa", true)
	insert(t, store, "sessions", session)
	principal := &auth.Principal{Identity: identity, Session: session}
	signing, _ := testRSAKey()
	config := OAuthProviderConfig{
		Store: store, Issuer: origin + "/oidc", JWKS: core.NewObject("keys", []any{signing}), EncryptionKey: randomKey(),
		CookieKeys: []string{"test-key-with-at-least-32-characters-long"}, TrustedOrigins: []string{origin}, AllowInsecureLocalhost: true,
		ResourceServers: map[string]OAuthResourceServer{mcpAPI: {Scopes: []string{"mcp:tools"}}},
		Registration:    &RegistrationOptions{},
		Authenticate: func(_ context.Context, credential core.CredentialInput) (*auth.Principal, error) {
			if credential.Token != "admin" {
				return nil, core.NewIamError("UNAUTHENTICATED", "No", 401)
			}
			return principal, nil
		},
		Authorize: func(_ context.Context, credential core.CredentialInput, _ string, _ core.ResourceRef) error {
			if credential.Token != "admin" {
				return core.NewIamError("ACCESS_DENIED", "Forbidden", 403)
			}
			return nil
		},
		InteractionURL:   func(uid string) string { return origin + "/interactions/" + uid },
		RenderDevicePage: func(_ context.Context, input DevicePageInput) (string, error) { return input.Form, nil },
		RenderLogoutPage: func(_ context.Context, form string) (string, error) { return form, nil },
	}
	if configure != nil {
		configure(&config)
	}
	provider, err := CreateOAuthProvider(config)
	if err != nil {
		t.Fatal(err)
	}
	server.provider = provider
	f := &registrationFixture{oauthFixture: &oauthFixture{store: store, server: server, provider: provider, origin: origin, principal: principal}}
	f.publicClient = func() *core.Object {
		return core.NewObject("client_name", "MCP host", "redirect_uris", []any{origin + "/callback"}, "token_endpoint_auth_method", "none",
			"grant_types", []any{"authorization_code", "refresh_token"}, "response_types", []any{"code"})
	}
	return f
}

func (f *registrationFixture) register(t *testing.T, body *core.Object, headers map[string]string) (int, *core.Object) {
	t.Helper()
	all := map[string]string{"content-type": "application/json"}
	for key, value := range headers {
		all[key] = value
	}
	result := fetch(t, "POST", f.origin+"/oidc/reg", all, stringify(body))
	parsed, err := core.ParseJSONString(result.Body)
	object, _ := parsed.(*core.Object)
	if err != nil || object == nil {
		object = core.NewObject("text", result.Body)
	}
	return result.Status, object
}

func with(base *core.Object, pairs ...any) *core.Object {
	out := base.Clone()
	for index := 0; index+1 < len(pairs); index += 2 {
		out.Set(pairs[index].(string), pairs[index+1])
	}
	return out
}

func TestRegistrationWithTenantTokens(t *testing.T) {
	f := newRegistrationFixture(t, nil)
	ctx := context.Background()
	discovery := fetch(t, "GET", f.origin+"/oidc/.well-known/openid-configuration", nil, "").JSON(t)
	if str(discovery, "registration_endpoint") != f.origin+"/oidc/reg" || !contains(stringList(discovery.Get("code_challenge_methods_supported")), "S256") {
		t.Fatalf("unexpected discovery %s", stringify(discovery))
	}
	issued, err := f.provider.CreateRegistrationToken(ctx, admin, CreateRegistrationTokenInput{TenantID: "a", Name: "Claude",
		Scopes: []string{"openid", "offline_access", "mcp:tools"}, Resources: []string{mcpAPI}})
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(issued.Token) || issued.MaxClients != 1 || issued.Used != 0 || issued.AllowConfidential {
		t.Fatalf("unexpected token %+v", issued)
	}
	if status, _ := f.register(t, f.publicClient(), nil); status != 401 {
		t.Fatalf("expected 401 without a token, got %d", status)
	}
	bearer := map[string]string{"authorization": "Bearer " + issued.Token}
	status, registered := f.register(t, with(f.publicClient(), "tenant_id", "b"), bearer)
	if status != 201 || str(registered, "client_name") != "MCP host" || str(registered, "token_endpoint_auth_method") != "none" ||
		str(registered, "scope") != "openid offline_access mcp:tools" || str(registered, "tenant_id") != "a" || registered.Has("client_secret") {
		t.Fatalf("unexpected registration %d %s", status, stringify(registered))
	}
	clientID := str(registered, "client_id")
	summary, err := f.provider.GetClient(ctx, admin, "a", clientID)
	if err != nil || summary.TenantID != "a" || !summary.Public || stringify(anyList(summary.Resources)) != `["`+mcpAPI+`"]` || summary.RegisteredVia != issued.ID {
		t.Fatalf("unexpected client %+v %v", summary, err)
	}
	_, err = f.provider.GetClient(ctx, admin, "b", clientID)
	expectIamError(t, err, 404, "")
	if status, _ := f.register(t, f.publicClient(), bearer); status != 401 {
		t.Fatalf("expected the token used up, got %d", status)
	}
	tokens, _ := f.provider.ListRegistrationTokens(ctx, admin, "a")
	if len(tokens) != 1 || tokens[0].ID != issued.ID || tokens[0].Used != 1 || tokens[0].Name != "Claude" {
		t.Fatalf("unexpected tokens %+v", tokens)
	}
	stored, _ := f.store.Find(ctx, "oauthRegistrationTokens", nil, nil)
	if strings.Contains(stringify(anyObjects(stored)), issued.Token) {
		t.Fatal("the registration token is stored in clear")
	}
	verifier, challenge := pkcePair()
	b := newBrowser(t)
	result := b.visit("GET", f.origin+"/oidc/auth?"+form("client_id", clientID, "response_type", "code", "redirect_uri", f.origin+"/callback",
		"scope", "mcp:tools offline_access", "resource", mcpAPI, "prompt", "consent", "code_challenge", challenge, "code_challenge_method", "S256"), nil, "")
	redirect := result.Header.Get("location")
	result = b.visit("POST", resolve(f.origin, redirect), map[string]string{"origin": f.origin}, "")
	redirect = result.Header.Get("location")
	for i := 0; i < 5 && !strings.Contains(redirect, "/callback?"); i++ {
		result = b.visit("GET", resolve(f.origin, redirect), nil, "")
		redirect = result.Header.Get("location")
	}
	code := queryValue(resolve(f.origin, redirect), "code")
	tokenResponse := fetch(t, "POST", f.origin+"/oidc/token", map[string]string{"content-type": formType}, form("grant_type", "authorization_code",
		"client_id", clientID, "code", code, "code_verifier", verifier, "redirect_uri", f.origin+"/callback", "resource", mcpAPI))
	if tokenResponse.Status != 200 {
		t.Fatalf("token status %d %s", tokenResponse.Status, tokenResponse.Body)
	}
	_, public := testRSAKey()
	verifierKey := public.Clone()
	verifierKey.Delete("use")
	tokenVerifier, _ := CreateAccessTokenVerifier(AccessTokenVerifierOptions{Issuer: f.origin + "/oidc", Audience: []string{mcpAPI}, JWKS: core.NewObject("keys", []any{verifierKey})})
	verified, err := tokenVerifier.Verify(ctx, str(tokenResponse.JSON(t), "access_token"), []string{"mcp:tools"})
	if err != nil || verified.Subject != "user-a" || verified.ClientID != clientID || verified.TenantID != "a" {
		t.Fatalf("unexpected verification %+v %v", verified, err)
	}
	actions := auditActions(t, f.store, "a")
	if !contains(actions, "iam:oauth:CreateRegistrationToken") || !contains(actions, "iam:oauth:RegisterClient") {
		t.Fatalf("missing audit events %v", actions)
	}
}

func queryValue(target, name string) string {
	parsed, err := parseURL(target)
	if err != nil {
		return ""
	}
	value, _ := newSearchParams(parsed.RawQuery).get(name)
	return value
}

func TestRegistrationOutsideTokenLimits(t *testing.T) {
	f := newRegistrationFixture(t, nil)
	ctx := context.Background()
	issued, err := f.provider.CreateRegistrationToken(ctx, admin, CreateRegistrationTokenInput{TenantID: "a", Name: "Many", MaxClients: int64Ptr(20)})
	if err != nil {
		t.Fatal(err)
	}
	bearer := map[string]string{"authorization": "Bearer " + issued.Token}
	refused := func(body *core.Object) string {
		t.Helper()
		status, result := f.register(t, body, bearer)
		if status != 400 {
			t.Fatalf("expected 400, got %d %s", status, stringify(result))
		}
		return str(result, "error")
	}
	withoutMethod := f.publicClient()
	withoutMethod.Delete("token_endpoint_auth_method")
	for _, body := range []*core.Object{
		withoutMethod,
		with(f.publicClient(), "grant_types", []any{"client_credentials"}),
		with(f.publicClient(), "redirect_uris", []any{"http://evil.example.test/cb"}),
		with(f.publicClient(), "jwks_uri", "https://keys.example.test/jwks"),
		with(f.publicClient(), "scope", "openid iam"),
	} {
		if code := refused(body); code != "invalid_client_metadata" {
			t.Fatalf("expected invalid_client_metadata, got %s for %s", code, stringify(body))
		}
	}
	status, native := f.register(t, with(f.publicClient(), "application_type", "native", "redirect_uris", []any{"com.example.desktop:/oauth/callback"}), bearer)
	if status != 201 || str(native, "scope") != "openid profile email offline_access" {
		t.Fatalf("unexpected native registration %d %s", status, stringify(native))
	}
	tokens, _ := f.provider.ListRegistrationTokens(ctx, admin, "a")
	if err := f.provider.RevokeRegistrationToken(ctx, admin, "a", tokens[0].ID); err != nil {
		t.Fatal(err)
	}
	if status, _ := f.register(t, f.publicClient(), bearer); status != 401 {
		t.Fatalf("expected a revoked token refused, got %d", status)
	}
	_, err = f.provider.CreateRegistrationToken(ctx, admin, CreateRegistrationTokenInput{TenantID: "a", Name: "X", Scopes: []string{"nope"}})
	expectIamError(t, err, 0, "INVALID_INPUT")
	_, err = f.provider.CreateRegistrationToken(ctx, core.CredentialInput{Token: "member"}, CreateRegistrationTokenInput{TenantID: "a", Name: "X"})
	expectIamError(t, err, 403, "")
	err = f.provider.RevokeRegistrationToken(ctx, admin, "b", tokens[0].ID)
	expectIamError(t, err, 404, "")
}

func TestAnonymousRegistration(t *testing.T) {
	f := newRegistrationFixture(t, func(config *OAuthProviderConfig) {
		config.Registration = &RegistrationOptions{Anonymous: func(_ context.Context, request AnonymousRegistrationRequest) (*RegistrationPolicy, error) {
			if request.Headers.Get("x-tenant") == "a" {
				return &RegistrationPolicy{TenantID: "a", MaxClients: int64Ptr(1), Scopes: []string{"openid"}}, nil
			}
			return nil, nil
		}}
	})
	if status, _ := f.register(t, f.publicClient(), nil); status != 401 {
		t.Fatalf("expected 401, got %d", status)
	}
	status, first := f.register(t, f.publicClient(), map[string]string{"x-tenant": "a"})
	if status != 201 || str(first, "tenant_id") != "a" || str(first, "scope") != "openid" {
		t.Fatalf("unexpected registration %d %s", status, stringify(first))
	}
	status, second := f.register(t, f.publicClient(), map[string]string{"x-tenant": "a"})
	if status != 400 || str(second, "error") != "access_denied" {
		t.Fatalf("expected access_denied, got %d %s", status, stringify(second))
	}
	clients, _ := f.provider.ListClients(context.Background(), admin, "a", false)
	if len(clients) != 1 || clients[0].RegisteredVia != "anonymous" {
		t.Fatalf("unexpected clients %+v", clients)
	}
}

func TestRegistrationClosedUnlessConfigured(t *testing.T) {
	f := newRegistrationFixture(t, func(config *OAuthProviderConfig) { config.Registration = nil })
	discovery := fetch(t, "GET", f.origin+"/oidc/.well-known/openid-configuration", nil, "").JSON(t)
	if discovery.Has("registration_endpoint") {
		t.Fatal("registration advertised")
	}
	if status, _ := f.register(t, f.publicClient(), nil); status < 400 {
		t.Fatalf("expected a refusal, got %d", status)
	}
}

func TestProtectedResourceMetadata(t *testing.T) {
	options := ProtectedResourceMetadataOptions{Resource: mcpAPI, AuthorizationServers: []string{"https://id.example.test/oidc"},
		Scopes: []string{"mcp:tools"}, ResourceName: "Acme MCP"}
	if u, _ := ProtectedResourceMetadataURL(mcpAPI); u != "https://mcp.example.test/.well-known/oauth-protected-resource/mcp" {
		t.Fatalf("unexpected URL %s", u)
	}
	if u, _ := ProtectedResourceMetadataURL("https://api.example.test/"); u != "https://api.example.test/.well-known/oauth-protected-resource" {
		t.Fatalf("unexpected URL %s", u)
	}
	metadata, err := ProtectedResourceMetadata(options)
	if err != nil || str(metadata, "resource") != mcpAPI || stringify(metadata.Get("authorization_servers")) != `["https://id.example.test/oidc"]` ||
		stringify(metadata.Get("scopes_supported")) != `["mcp:tools"]` || stringify(metadata.Get("bearer_methods_supported")) != `["header"]` ||
		str(metadata, "resource_name") != "Acme MCP" {
		t.Fatalf("unexpected metadata %s %v", stringify(metadata), err)
	}
	handler, err := CreateProtectedResourceHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	metadataURL, _ := ProtectedResourceMetadataURL(mcpAPI)
	served := handler(httptest.NewRequest("GET", metadataURL, nil))
	if served == nil || served.Status != 200 || served.Header.Get("access-control-allow-origin") != "*" || str(mustParse(t, string(served.Body)), "resource") != mcpAPI {
		t.Fatalf("unexpected served metadata %+v", served)
	}
	if handler(httptest.NewRequest("GET", mcpAPI, nil)) != nil {
		t.Fatal("expected other paths left alone")
	}
	if response := handler(httptest.NewRequest("POST", metadataURL, nil)); response == nil || response.Status != 405 {
		t.Fatalf("expected 405, got %+v", response)
	}
	empty := options
	empty.AuthorizationServers = nil
	if _, err := ProtectedResourceMetadata(empty); err == nil {
		t.Fatal("expected an error without authorization servers")
	}
	verifier, _ := CreateAccessTokenVerifier(AccessTokenVerifierOptions{Issuer: "https://id.example.test/oidc", Audience: []string{mcpAPI}, JWKS: core.NewObject("keys", []any{})})
	challenge := verifier.Challenge(core.NewIamError("INSUFFICIENT_SCOPE", "x", 403), "", metadataURL, []string{"mcp:tools"})
	if !strings.Contains(challenge, `Bearer error="insufficient_scope", resource_metadata="https://mcp.example.test/.well-known/oauth-protected-resource/mcp", scope="mcp:tools"`) {
		t.Fatalf("unexpected challenge %s", challenge)
	}
}

func TestResourceGuard(t *testing.T) {
	const issuer = "https://id.example.test/oidc"
	signing, public := testRSAKey()
	verifierKey := public.Clone()
	verifierKey.Delete("use")
	guard, err := CreateResourceGuard(ResourceGuardOptions{ProtectedResourceMetadataOptions: ProtectedResourceMetadataOptions{Resource: mcpAPI,
		AuthorizationServers: []string{issuer}, Scopes: []string{"mcp:tools", "mcp:admin"}}, RequiredScopes: []string{"mcp:tools"},
		JWKS: core.NewObject("keys", []any{verifierKey})})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sign := func(scope, audience string) string {
		now := epoch(wallNow())
		return signJWT(t, signing, "RS256", core.NewObject("kid", "test-key", "typ", "at+jwt"), core.NewObject("client_id", "mcp-host",
			"scope", scope, "tenant_id", "a", "iss", issuer, "aud", audience, "sub", "user-a", "iat", now, "exp", now+300))
	}
	call := func(authorization string, scopes []string) (*Response, *VerifiedAccessToken) {
		request := httptest.NewRequest("GET", mcpAPI, nil)
		if authorization != "" {
			request.Header.Set("authorization", authorization)
		}
		response, token, err := guard.Check(ctx, request, scopes)
		if err != nil {
			t.Fatal(err)
		}
		return response, token
	}
	if metadata, _, _ := guard.Check(ctx, httptest.NewRequest("GET", guard.MetadataURL, nil), nil); metadata == nil || metadata.Status != 200 {
		t.Fatalf("unexpected metadata %+v", metadata)
	}
	anonymous, _ := call("", nil)
	if anonymous.Status != 401 || anonymous.Header.Get("www-authenticate") != `Bearer resource_metadata="`+guard.MetadataURL+`", scope="mcp:tools"` {
		t.Fatalf("unexpected anonymous challenge %d %s", anonymous.Status, anonymous.Header.Get("www-authenticate"))
	}
	forged, _ := call("Bearer not.a.token", nil)
	if forged.Status != 401 || !strings.Contains(forged.Header.Get("www-authenticate"), `error="invalid_token"`) {
		t.Fatalf("unexpected forged response %d %s", forged.Status, forged.Header.Get("www-authenticate"))
	}
	if other, _ := call("Bearer "+sign("mcp:tools", "https://other.example.test"), nil); other.Status != 401 {
		t.Fatalf("expected 401 for another audience, got %d", other.Status)
	}
	narrow, _ := call("Bearer "+sign("mcp:tools", mcpAPI), []string{"mcp:admin"})
	if narrow.Status != 403 || str(mustParse(t, string(narrow.Body)), "error") != "insufficient_scope" ||
		!strings.Contains(narrow.Header.Get("www-authenticate"), `scope="mcp:tools mcp:admin"`) {
		t.Fatalf("unexpected narrow response %d %s %s", narrow.Status, narrow.Body, narrow.Header.Get("www-authenticate"))
	}
	allowed, token := call("Bearer "+sign("mcp:tools mcp:admin", mcpAPI), nil)
	if allowed != nil || token == nil || token.Subject != "user-a" || token.ClientID != "mcp-host" || token.TenantID != "a" {
		t.Fatalf("unexpected allowed result %+v %+v", allowed, token)
	}
	_ = http.MethodGet
}
