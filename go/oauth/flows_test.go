package oauth

// The provider flows the TypeScript suite covers through a whole deployment (tests/oauth-mcp-integration.test.ts:
// RFC 8414 discovery at the root, anonymous registration, a resource token for a guarded MCP server, and the grant
// ending with the IAM session), plus the device flow and RP-initiated logout the configuration enables.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

func TestMCPAuthorizationEndToEnd(t *testing.T) {
	var resource string
	f := newOAuthFixture(t, func(config *OAuthProviderConfig) {
		resource = strings.TrimSuffix(config.Issuer, "/oidc") + "/mcp"
		config.ResourceServers = map[string]OAuthResourceServer{resource: {Scopes: []string{"mcp:tools"}}}
		config.Registration = &RegistrationOptions{Anonymous: func(context.Context, AnonymousRegistrationRequest) (*RegistrationPolicy, error) {
			return &RegistrationPolicy{TenantID: "a", Scopes: []string{"openid", "offline_access", "mcp:tools"}, Resources: []string{resource}}, nil
		}}
	})
	ctx := context.Background()
	guard, err := CreateResourceGuard(ResourceGuardOptions{ProtectedResourceMetadataOptions: ProtectedResourceMetadataOptions{Resource: resource,
		AuthorizationServers: []string{f.origin + "/oidc"}, Scopes: []string{"mcp:tools"}}, RequiredScopes: []string{"mcp:tools"}})
	if err != nil {
		t.Fatal(err)
	}
	mcp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.Clone(r.Context())
		target.URL, _ = url.Parse(resource + strings.TrimPrefix(r.URL.RequestURI(), "/mcp"))
		if strings.HasPrefix(r.URL.Path, "/.well-known/") {
			target.URL, _ = url.Parse(f.origin + r.URL.RequestURI())
		}
		response, token, err := guard.Check(r.Context(), target, nil)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		if response == nil {
			response = jsonResponse(200, core.NewObject("jsonrpc", "2.0", "result", core.NewObject("user", token.Subject, "tenant", token.TenantID)), nil)
		}
		response.WriteTo(w)
	}))
	defer mcp.Close()
	first := fetch(t, "GET", mcp.URL+"/mcp", nil, "")
	if first.Status != 401 {
		t.Fatalf("expected 401, got %d", first.Status)
	}
	metadataURL := regexp.MustCompile(`resource_metadata="([^"]+)"`).FindStringSubmatch(first.Header.Get("www-authenticate"))[1]
	if metadataURL != f.origin+"/.well-known/oauth-protected-resource/mcp" {
		t.Fatalf("unexpected metadata URL %s", metadataURL)
	}
	server8414 := fetch(t, "GET", f.origin+"/.well-known/oauth-authorization-server/oidc", nil, "").JSON(t)
	if str(server8414, "issuer") != f.origin+"/oidc" || !contains(stringList(server8414.Get("code_challenge_methods_supported")), "S256") {
		t.Fatalf("unexpected RFC 8414 metadata %s", stringify(server8414))
	}
	// The RFC 8414 path is outside the issuer path, so its endpoints are at the root, where the provider also answers.
	if str(server8414, "registration_endpoint") != f.origin+"/reg" {
		t.Fatalf("unexpected registration endpoint %s", str(server8414, "registration_endpoint"))
	}
	registration := fetch(t, "POST", str(server8414, "registration_endpoint"), map[string]string{"content-type": "application/json"},
		stringify(core.NewObject("client_name", "Example MCP host", "redirect_uris", []any{f.origin + "/callback"}, "token_endpoint_auth_method", "none",
			"grant_types", []any{"authorization_code", "refresh_token"}, "response_types", []any{"code"})))
	if registration.Status != 201 {
		t.Fatalf("registration status %d %s", registration.Status, registration.Body)
	}
	clientID := str(registration.JSON(t), "client_id")
	verifier, challenge := pkcePair()
	b := newBrowser(t)
	step := b.visit("GET", str(server8414, "authorization_endpoint")+"?"+form("client_id", clientID, "response_type", "code",
		"redirect_uri", f.origin+"/callback", "scope", "mcp:tools offline_access", "resource", resource, "code_challenge", challenge,
		"code_challenge_method", "S256", "state", "xyz"), nil, "")
	location := step.Header.Get("location")
	details := b.visit("GET", resolve(f.origin, location), nil, "").JSON(t)
	if str(details, "tenantId") != "a" || str(details, "clientName") != "Example MCP host" || stringify(details.Get("resources")) != `["`+resource+`"]` {
		t.Fatalf("unexpected details %s", stringify(details))
	}
	step = b.visit("POST", resolve(f.origin, location), map[string]string{"origin": f.origin}, "")
	location = step.Header.Get("location")
	for i := 0; i < 5 && !strings.Contains(location, "/callback?"); i++ {
		step = b.visit("GET", resolve(f.origin, location), nil, "")
		location = step.Header.Get("location")
	}
	callback := resolve(f.origin, location)
	if queryValue(callback, "state") != "xyz" {
		t.Fatalf("unexpected callback %s (%d %s)", callback, step.Status, step.Body)
	}
	tokenResponse := fetch(t, "POST", str(server8414, "token_endpoint"), map[string]string{"content-type": formType}, form("grant_type", "authorization_code",
		"client_id", clientID, "code", queryValue(callback, "code"), "code_verifier", verifier, "redirect_uri", f.origin+"/callback", "resource", resource))
	tokens := tokenResponse.JSON(t)
	if tokenResponse.Status != 200 || str(tokens, "refresh_token") == "" {
		t.Fatalf("token status %d %s", tokenResponse.Status, tokenResponse.Body)
	}
	call := fetch(t, "GET", mcp.URL+"/mcp", map[string]string{"authorization": "Bearer " + str(tokens, "access_token")}, "")
	if call.Status != 200 || stringify(obj(call.JSON(t), "result")) != `{"user":"user-a","tenant":"a"}` {
		t.Fatalf("unexpected MCP call %d %s", call.Status, call.Body)
	}
	remove(t, f.store, "sessions", "session-a")
	if _, err := f.provider.LogoutEndedSessions(ctx, ""); err != nil {
		t.Fatal(err)
	}
	refreshed := fetch(t, "POST", str(server8414, "token_endpoint"), map[string]string{"content-type": formType},
		form("grant_type", "refresh_token", "client_id", clientID, "refresh_token", str(tokens, "refresh_token")))
	if refreshed.Status != 400 {
		t.Fatalf("expected the refresh refused after sign-out, got %d %s", refreshed.Status, refreshed.Body)
	}
}

func TestDeviceAuthorizationFlow(t *testing.T) {
	f := newOAuthFixture(t, nil)
	ctx := context.Background()
	if _, err := f.provider.RegisterClient(ctx, admin, RegisterOAuthClient{TenantID: "a", ClientID: "tv", Public: true,
		OAuthClientSettings: OAuthClientSettings{Name: "Living room TV", RedirectURIs: []string{}, GrantTypes: []string{deviceCodeGrant, "refresh_token"},
			Scopes: []string{"openid", "profile", "offline_access"}}}); err != nil {
		t.Fatal(err)
	}
	authorization := fetch(t, "POST", f.origin+"/oidc/device/auth", map[string]string{"content-type": formType}, form("client_id", "tv", "scope", "openid profile"))
	if authorization.Status != 200 {
		t.Fatalf("device authorization status %d %s", authorization.Status, authorization.Body)
	}
	device := authorization.JSON(t)
	userCode := str(device, "user_code")
	if !regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$`).MatchString(userCode) ||
		str(device, "verification_uri") != f.origin+"/oidc/device" || device.Get("expires_in") != float64(600) ||
		str(device, "verification_uri_complete") != f.origin+"/oidc/device?user_code="+userCode {
		t.Fatalf("unexpected device authorization %s", authorization.Body)
	}
	poll := func() *httpResult {
		return f.token(t, form("grant_type", deviceCodeGrant, "client_id", "tv", "device_code", str(device, "device_code")), nil)
	}
	if pending := poll(); pending.Status != 400 || str(pending.JSON(t), "error") != "authorization_pending" {
		t.Fatalf("expected authorization_pending, got %d %s", pending.Status, pending.Body)
	}
	b := newBrowser(t)
	page := b.visit("GET", f.origin+"/oidc/device", nil, "")
	xsrf := regexp.MustCompile(`name="xsrf" value="([0-9a-f]+)"`).FindStringSubmatch(page.Body)
	if page.Status != 200 || xsrf == nil || !strings.Contains(page.Body, "op.deviceInputForm") {
		t.Fatalf("unexpected input page %d %s", page.Status, page.Body)
	}
	wrong := b.visit("POST", f.origin+"/oidc/device", map[string]string{"content-type": formType}, form("xsrf", xsrf[1], "user_code", "BCDF-GHJK"))
	if wrong.Status != 200 || !strings.Contains(wrong.Body, "op.deviceInputForm") {
		t.Fatalf("expected the input page again, got %d %s", wrong.Status, wrong.Body)
	}
	xsrf = regexp.MustCompile(`name="xsrf" value="([0-9a-f]+)"`).FindStringSubmatch(wrong.Body)
	confirm := b.visit("POST", f.origin+"/oidc/device", map[string]string{"content-type": formType}, form("xsrf", xsrf[1], "user_code", strings.ToLower(userCode)))
	if confirm.Status != 200 || !strings.Contains(confirm.Body, "op.deviceConfirmForm") {
		t.Fatalf("expected the confirmation page, got %d %s", confirm.Status, confirm.Body)
	}
	xsrf = regexp.MustCompile(`name="xsrf" value="([0-9a-f]+)"`).FindStringSubmatch(confirm.Body)
	confirmed := b.visit("POST", f.origin+"/oidc/device", map[string]string{"content-type": formType}, form("xsrf", xsrf[1], "user_code", userCode, "confirm", "yes"))
	location := confirmed.Header.Get("location")
	if confirmed.Status != 303 || !strings.Contains(location, "/interactions/") {
		t.Fatalf("expected an interaction, got %d %s %s", confirmed.Status, location, confirmed.Body)
	}
	finished := b.visit("POST", resolve(f.origin, location), map[string]string{"origin": f.origin}, "")
	resumed := b.visit("GET", resolve(f.origin, finished.Header.Get("location")), nil, "")
	if resumed.Status != 200 || !strings.Contains(resumed.Body, "<html>") {
		t.Fatalf("expected the success page, got %d %s", resumed.Status, resumed.Body)
	}
	tokens := poll()
	if tokens.Status != 200 || str(tokens.JSON(t), "id_token") == "" {
		t.Fatalf("expected tokens, got %d %s", tokens.Status, tokens.Body)
	}
	if again := poll(); again.Status != 400 || str(again.JSON(t), "error") != "invalid_grant" {
		t.Fatalf("expected a consumed device code refused, got %d %s", again.Status, again.Body)
	}
}

func TestRPInitiatedLogout(t *testing.T) {
	f := newOAuthFixture(t, nil)
	ctx := context.Background()
	if _, err := f.provider.RegisterClient(ctx, admin, RegisterOAuthClient{TenantID: "a", ClientID: "web", Public: true,
		OAuthClientSettings: OAuthClientSettings{Name: "Web", RedirectURIs: []string{f.origin + "/callback"}, PostLogoutRedirectURIs: []string{f.origin + "/bye"}}}); err != nil {
		t.Fatal(err)
	}
	b := newBrowser(t)
	_, challenge := pkcePair()
	authorize(t, b, f.origin, f.origin+"/oidc/auth?"+form("client_id", "web", "response_type", "code", "redirect_uri", f.origin+"/callback",
		"scope", "openid", "code_challenge", challenge, "code_challenge_method", "S256"))
	unknown := b.visit("GET", f.origin+"/oidc/session/end?"+form("client_id", "web", "post_logout_redirect_uri", "https://evil.example.test/"), nil, "")
	if unknown.Status != 400 {
		t.Fatalf("expected an unregistered post-logout URI refused, got %d %s", unknown.Status, unknown.Body)
	}
	page := b.visit("GET", f.origin+"/oidc/session/end?"+form("client_id", "web", "post_logout_redirect_uri", f.origin+"/bye", "state", "s1"), nil, "")
	xsrf := regexp.MustCompile(`name="xsrf" value="([0-9a-f]+)"`).FindStringSubmatch(page.Body)
	if page.Status != 200 || xsrf == nil || !strings.Contains(page.Body, "op.logoutForm") {
		t.Fatalf("unexpected logout page %d %s", page.Status, page.Body)
	}
	confirmed := b.visit("POST", f.origin+"/oidc/session/end/confirm", map[string]string{"content-type": formType}, form("xsrf", xsrf[1], "logout", "yes"))
	if confirmed.Status != 303 || confirmed.Header.Get("location") != f.origin+"/bye?state=s1" {
		t.Fatalf("unexpected confirmation %d %s %s", confirmed.Status, confirmed.Header.Get("location"), confirmed.Body)
	}
	if grants, _ := f.provider.ListGrants(ctx, admin, "a", "", ""); len(grants) != 0 {
		t.Fatalf("expected the session's grants revoked, got %d", len(grants))
	}
	success := fetch(t, "GET", f.origin+"/oidc/session/end/success?client_id=web", nil, "")
	if success.Status != 200 || !strings.Contains(success.Body, "Your sign-out with Web was successful.") {
		t.Fatalf("unexpected success page %d %s", success.Status, success.Body)
	}
}
