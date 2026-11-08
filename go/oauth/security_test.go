package oauth

// Port of tests/security-oauth.test.ts.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const reportsAPI = "https://reports.example.test"

func newSecurityFixture(t *testing.T, configure func(config *OAuthProviderConfig)) *oauthFixture {
	t.Helper()
	store := newTestStore(t)
	now := wallNow()
	insert(t, store, "tenants", core.NewObject("id", "root", "tenantId", "root", "name", "root", "type", "root", "parentId", nil, "status", "active", "createdAt", now))
	insert(t, store, "tenants", core.NewObject("id", "a", "tenantId", "a", "name", "a", "type", "organization", "parentId", "root", "status", "active", "createdAt", now))
	insert(t, store, "identities", core.NewObject("id", "user-a", "tenantId", "a", "name", "user-a", "kind", "user", "email", "user-a@example.test",
		"emailVerified", true, "status", "active", "rootAdmin", false, "owner", false, "createdAt", now))
	insert(t, store, "identities", core.NewObject("id", "service-a", "tenantId", "a", "name", "service-a", "kind", "service",
		"emailVerified", false, "status", "active", "rootAdmin", false, "owner", false, "createdAt", now))
	server := newProviderServer(t)
	origin := server.URL
	identity, _ := store.Get(context.Background(), "identities", "user-a")
	session := core.NewObject("id", "session-a", "tenantId", "a", "identityId", "user-a", "kind", "user", "tokenHash", "x",
		"createdAt", now, "authenticatedAt", now, "lastSeenAt", now, "expiresAt", now+100000, "mfa", true)
	insert(t, store, "sessions", session)
	principal := &auth.Principal{Identity: identity, Session: session}
	signing, _ := testRSAKey()
	config := OAuthProviderConfig{
		Store: store, Issuer: origin + "/oidc", JWKS: core.NewObject("keys", []any{signing}), EncryptionKey: randomKey(),
		CookieKeys: []string{"test-key-with-at-least-32-characters-long"}, TrustedOrigins: []string{origin}, AllowInsecureLocalhost: true,
		ResourceServers: map[string]OAuthResourceServer{testAPI: {Scopes: []string{"invoices:read"}}, reportsAPI: {Scopes: []string{"reports:read"}}},
		Authenticate: func(_ context.Context, credential core.CredentialInput) (*auth.Principal, error) {
			if credential.Token != "admin" {
				return nil, core.NewIamError("UNAUTHENTICATED", "no", 401)
			}
			return principal, nil
		},
		Authorize: func(_ context.Context, credential core.CredentialInput, _ string, _ core.ResourceRef) error {
			if credential.Token != "admin" {
				return core.NewIamError("ACCESS_DENIED", "no", 403)
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
	return &oauthFixture{store: store, server: server, provider: provider, origin: origin, principal: principal}
}

// personalToken is a person's authorization-code token for a confidential client, for the API resource.
func (f *oauthFixture) personalToken(t *testing.T, clientID, secret string) string {
	t.Helper()
	verifier, challenge := pkcePair()
	b := newBrowser(t)
	result := b.visit("GET", f.origin+"/oidc/auth?"+form("client_id", clientID, "response_type", "code", "redirect_uri", f.origin+"/callback",
		"scope", "openid invoices:read", "prompt", "consent", "state", "state", "resource", testAPI, "code_challenge", challenge,
		"code_challenge_method", "S256"), nil, "")
	redirect := result.Header.Get("location")
	b.visit("GET", resolve(f.origin, redirect), nil, "")
	result = b.visit("POST", resolve(f.origin, redirect), map[string]string{"origin": f.origin}, "")
	redirect = result.Header.Get("location")
	for i := 0; i < 5 && !strings.Contains(redirect, "/callback?"); i++ {
		result = b.visit("GET", resolve(f.origin, redirect), nil, "")
		redirect = result.Header.Get("location")
	}
	code := queryValue(resolve(f.origin, redirect), "code")
	response := f.token(t, form("grant_type", "authorization_code", "client_id", clientID, "code", code, "code_verifier", verifier,
		"redirect_uri", f.origin+"/callback", "resource", testAPI), map[string]string{"authorization": basicAuth(clientID, secret)})
	if response.Status != 200 {
		t.Fatalf("token status %d %s", response.Status, response.Body)
	}
	return str(response.JSON(t), "access_token")
}

func TestServiceAccountOnlyOnClientTokens(t *testing.T) {
	f := newSecurityFixture(t, nil)
	ctx := context.Background()
	web, err := f.provider.RegisterClient(ctx, admin, RegisterOAuthClient{TenantID: "a", ClientID: "web", ServiceAccountID: "service-a",
		OAuthClientSettings: OAuthClientSettings{Name: "Web", GrantTypes: []string{"authorization_code", "refresh_token", "client_credentials"},
			RedirectURIs: []string{f.origin + "/callback"}, Scopes: []string{"openid", "invoices:read"}, Resources: []string{testAPI}}})
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := f.provider.RegisterClient(ctx, admin, RegisterOAuthClient{TenantID: "a", ClientID: "gateway",
		OAuthClientSettings: OAuthClientSettings{Name: "Gateway", RedirectURIs: []string{}, GrantTypes: []string{tokenExchangeGrant},
			Scopes: []string{"reports:read"}, Resources: []string{reportsAPI}}})
	if err != nil {
		t.Fatal(err)
	}
	personal := f.personalToken(t, "web", web.ClientSecret)
	claims := decodePayload(t, personal)
	if str(claims, "sub") != "user-a" || claims.Has("identity_id") {
		t.Fatalf("unexpected personal token %s", stringify(claims))
	}
	_, public := testRSAKey()
	view, _ := CreateAccessTokenVerifier(AccessTokenVerifierOptions{Issuer: f.origin + "/oidc", Audience: []string{testAPI}, JWKS: core.NewObject("keys", []any{public})})
	verified, err := view.Verify(ctx, personal, nil)
	if err != nil || verified.IdentityID != "" {
		t.Fatalf("unexpected view %+v %v", verified, err)
	}
	exchanged := f.token(t, form("grant_type", tokenExchangeGrant, "subject_token_type", accessTokenType, "subject_token", personal, "resource", reportsAPI),
		map[string]string{"authorization": basicAuth("gateway", gateway.ClientSecret)}).JSON(t)
	if str(decodePayload(t, str(exchanged, "access_token")), "sub") != "user-a" {
		t.Fatalf("unexpected exchanged token %s", stringify(exchanged))
	}
	own := f.token(t, form("grant_type", "client_credentials", "resource", testAPI, "scope", "invoices:read"),
		map[string]string{"authorization": basicAuth("web", web.ClientSecret)}).JSON(t)
	if str(decodePayload(t, str(own, "access_token")), "identity_id") != "service-a" {
		t.Fatalf("expected the service account on the client's own token, got %s", stringify(own))
	}
}

func TestExchangeRefusedAfterDisconnectAndForDPoPClients(t *testing.T) {
	f := newSecurityFixture(t, nil)
	ctx := context.Background()
	web, err := f.provider.RegisterClient(ctx, admin, RegisterOAuthClient{TenantID: "a", ClientID: "web",
		OAuthClientSettings: OAuthClientSettings{Name: "Web", RedirectURIs: []string{f.origin + "/callback"}, Scopes: []string{"openid", "invoices:read"}, Resources: []string{testAPI}}})
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := f.provider.RegisterClient(ctx, admin, RegisterOAuthClient{TenantID: "a", ClientID: "gateway",
		OAuthClientSettings: OAuthClientSettings{Name: "Gateway", RedirectURIs: []string{}, GrantTypes: []string{tokenExchangeGrant},
			Scopes: []string{"reports:read"}, Resources: []string{reportsAPI}}})
	if err != nil {
		t.Fatal(err)
	}
	strict, err := f.provider.RegisterClient(ctx, admin, RegisterOAuthClient{TenantID: "a", ClientID: "strict",
		OAuthClientSettings: OAuthClientSettings{Name: "Strict", RedirectURIs: []string{}, RequireDPoP: true, GrantTypes: []string{tokenExchangeGrant},
			Scopes: []string{"reports:read"}, Resources: []string{reportsAPI}}})
	if err != nil {
		t.Fatal(err)
	}
	personal := f.personalToken(t, "web", web.ClientSecret)
	exchange := func(clientID, secret string) *httpResult {
		return f.token(t, form("grant_type", tokenExchangeGrant, "subject_token_type", accessTokenType, "subject_token", personal, "resource", reportsAPI),
			map[string]string{"authorization": basicAuth(clientID, secret)})
	}
	if response := exchange("strict", strict.ClientSecret); response.Status != 400 {
		t.Fatalf("expected the DPoP-only client refused, got %d %s", response.Status, response.Body)
	}
	if response := exchange("gateway", gateway.ClientSecret); response.Status != 200 {
		t.Fatalf("exchange status %d %s", response.Status, response.Body)
	}
	if _, err := f.provider.RevokeGrants(ctx, admin, "a", "", "web"); err != nil {
		t.Fatal(err)
	}
	refused := exchange("gateway", gateway.ClientSecret)
	if refused.Status != 400 || str(refused.JSON(t), "error") != "invalid_grant" {
		t.Fatalf("expected invalid_grant after disconnecting, got %d %s", refused.Status, refused.Body)
	}
}

func TestOldSignInDoesNotAnswerMaxAge(t *testing.T) {
	f := newSecurityFixture(t, nil)
	if _, err := f.provider.RegisterClient(context.Background(), admin, RegisterOAuthClient{TenantID: "a", ClientID: "web", Public: true,
		OAuthClientSettings: OAuthClientSettings{Name: "Web", RedirectURIs: []string{f.origin + "/callback"}, Scopes: []string{"openid"}}}); err != nil {
		t.Fatal(err)
	}
	_, challenge := pkcePair()
	b := newBrowser(t)
	started := b.visit("GET", f.origin+"/oidc/auth?"+form("client_id", "web", "response_type", "code", "redirect_uri", f.origin+"/callback",
		"scope", "openid", "state", "state", "max_age", "0", "code_challenge", challenge, "code_challenge_method", "S256"), nil, "")
	interaction := resolve(f.origin, started.Header.Get("location"))
	if !strings.Contains(interaction, "/interactions/") {
		t.Fatalf("expected an interaction, got %d %s %s", started.Status, interaction, started.Body)
	}
	time.Sleep(5 * time.Millisecond)
	completed := b.visit("POST", interaction, map[string]string{"origin": f.origin}, "")
	if completed.Status != 401 {
		t.Fatalf("expected LOGIN_REQUIRED, got %d %s", completed.Status, completed.Body)
	}
}

func TestRegistrationGateEverySpelling(t *testing.T) {
	f := newSecurityFixture(t, func(config *OAuthProviderConfig) { config.Registration = &RegistrationOptions{} })
	body := `{"redirect_uris":["https://x.example.test/cb"],"token_endpoint_auth_method":"none","grant_types":["authorization_code"]}`
	for _, path := range []string{"/oidc/reg", "/oidc/REG", "/oidc/reg/", "/oidc/Reg", "/oidc/%72eg"} {
		response := fetch(t, "POST", f.origin+path, map[string]string{"content-type": "application/json"}, body)
		if response.Status != 401 && response.Status != 404 {
			t.Fatalf("%s: expected 401 or 404, got %d %s", path, response.Status, response.Body)
		}
		if response.Status == 401 && !strings.Contains(response.Header.Get("www-authenticate"), "invalid_token") {
			t.Fatalf("%s: expected an invalid_token challenge", path)
		}
	}
	if clients, _ := f.store.Find(context.Background(), "oauthClients", nil, nil); len(clients) != 0 {
		t.Fatalf("expected no clients, got %d", len(clients))
	}
}
