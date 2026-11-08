package oauth

// Port of tests/oauth-management.test.ts.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const testAPI = "https://api.example.test"

type managementFixture struct {
	*oauthFixture
	mu     sync.Mutex
	denied []string
}

func (m *managementFixture) wasDenied(action string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return contains(m.denied, action)
}

func newManagementFixture(t *testing.T, configure func(config *OAuthProviderConfig)) *managementFixture {
	t.Helper()
	store := newTestStore(t)
	now := wallNow()
	for _, id := range []string{"root", "a", "b"} {
		tenant := core.NewObject("id", id, "tenantId", id, "name", id, "type", "organization", "parentId", "root", "status", "active", "createdAt", now)
		if id == "root" {
			tenant.Set("type", "root")
			tenant.Set("parentId", nil)
		}
		insert(t, store, "tenants", tenant)
	}
	for _, row := range [][3]string{{"user-a", "a", "user"}, {"user-a2", "a", "user"}, {"user-b", "b", "user"}, {"service-a", "a", "service"}} {
		identity := core.NewObject("id", row[0], "tenantId", row[1], "name", row[0], "kind", row[2])
		if row[2] == "user" {
			identity.Set("email", row[0]+"@example.test")
		}
		identity.Set("emailVerified", row[2] == "user")
		identity.Set("status", "active")
		identity.Set("rootAdmin", false)
		identity.Set("owner", false)
		identity.Set("createdAt", now)
		insert(t, store, "identities", identity)
	}
	m := &managementFixture{}
	server := newProviderServer(t)
	origin := server.URL
	identity, _ := store.Get(context.Background(), "identities", "user-a")
	session := core.NewObject("id", "session-a", "tenantId", "a", "identityId", "user-a", "kind", "user", "tokenHash", "irrelevant",
		"createdAt", now, "authenticatedAt", now, "lastSeenAt", now, "expiresAt", now+100000, "mfa", true)
	insert(t, store, "sessions", session)
	principal := &auth.Principal{Identity: identity, Session: session}
	signing, _ := testRSAKey()
	key := randomKey()
	config := OAuthProviderConfig{
		Store: store, Issuer: origin + "/oidc", JWKS: core.NewObject("keys", []any{signing}), EncryptionKey: key,
		CookieKeys: []string{"test-key-with-at-least-32-characters-long"}, TrustedOrigins: []string{origin}, AllowInsecureLocalhost: true,
		ResourceServers: map[string]OAuthResourceServer{testAPI: {Scopes: []string{"invoices:read", "invoices:write"}}},
		Authenticate: func(_ context.Context, credential core.CredentialInput) (*auth.Principal, error) {
			if credential.Token != "admin" && credential.Token != "member" {
				return nil, core.NewIamError("UNAUTHENTICATED", "Unauthenticated", 401)
			}
			return principal, nil
		},
		Authorize: func(_ context.Context, credential core.CredentialInput, action string, _ core.ResourceRef) error {
			if credential.Token != "admin" {
				m.mu.Lock()
				m.denied = append(m.denied, action)
				m.mu.Unlock()
				return core.NewIamError("ACCESS_DENIED", "Forbidden", 403)
			}
			return nil
		},
		InteractionURL: func(uid string) string { return origin + "/interactions/" + uid },
		RenderDevicePage: func(_ context.Context, input DevicePageInput) (string, error) {
			return "<html><body>" + input.Form + "</body></html>", nil
		},
		RenderLogoutPage: func(_ context.Context, form string) (string, error) { return "<html><body>" + form + "</body></html>", nil },
	}
	if configure != nil {
		configure(&config)
	}
	provider, err := CreateOAuthProvider(config)
	if err != nil {
		t.Fatal(err)
	}
	server.provider = provider
	m.oauthFixture = &oauthFixture{store: store, server: server, provider: provider, origin: origin, key: key, principal: principal}
	return m
}

func (f *oauthFixture) token(t *testing.T, body string, headers map[string]string) *httpResult {
	t.Helper()
	all := map[string]string{"content-type": formType}
	for key, value := range headers {
		all[key] = value
	}
	return fetch(t, "POST", f.origin+"/oidc/token", all, body)
}

// authorizeFlow is the fixture browser's authorize(): consent, then the code exchange.
func (f *oauthFixture) authorizeFlow(t *testing.T, b *browser, clientID, scope string, authExtra, tokenExtra []string) (*core.Object, *core.Object) {
	t.Helper()
	verifier, challenge := pkcePair()
	params := append([]string{"client_id", clientID, "response_type", "code", "redirect_uri", f.origin + "/callback", "scope", scope,
		"prompt", "consent", "state", "state", "code_challenge", challenge, "code_challenge_method", "S256"}, authExtra...)
	result := b.visit("GET", f.origin+"/oidc/auth?"+form(params...), nil, "")
	redirect := result.Header.Get("location")
	if !strings.Contains(redirect, "/interactions/") {
		t.Fatalf("expected an interaction, got %d %q %s", result.Status, redirect, result.Body)
	}
	details := b.visit("GET", resolve(f.origin, redirect), nil, "").JSON(t)
	result = b.visit("POST", resolve(f.origin, redirect), map[string]string{"origin": f.origin}, "")
	redirect = result.Header.Get("location")
	for i := 0; i < 5 && !strings.Contains(redirect, "/callback?"); i++ {
		result = b.visit("GET", resolve(f.origin, redirect), nil, "")
		redirect = result.Header.Get("location")
	}
	callback, _ := url.Parse(resolve(f.origin, redirect))
	code := callback.Query().Get("code")
	if code == "" {
		t.Fatalf("no code: %d %q %s", result.Status, redirect, result.Body)
	}
	body := append([]string{"grant_type", "authorization_code", "client_id", clientID, "code", code, "code_verifier", verifier,
		"redirect_uri", f.origin + "/callback"}, tokenExtra...)
	response := f.token(t, form(body...), nil)
	if response.Status != 200 {
		t.Fatalf("token status %d %s", response.Status, response.Body)
	}
	return details, response.JSON(t)
}

func auditActions(t *testing.T, store core.IamStore, tenantID string) []string {
	t.Helper()
	events, err := store.Find(context.Background(), "audit", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, event := range events {
		out = append(out, str(event, "action"))
	}
	return out
}

func countOf(values []string, value string) int {
	count := 0
	for _, item := range values {
		if item == value {
			count++
		}
	}
	return count
}

func int64Ptr(value int64) *int64 { return &value }

func TestClientManagementWithoutExposingSecrets(t *testing.T) {
	f := newManagementFixture(t, nil)
	ctx := context.Background()
	member := core.CredentialInput{Token: "member"}
	registered, err := f.provider.RegisterClient(ctx, admin, RegisterOAuthClient{TenantID: "a", ClientID: "machine", ServiceAccountID: "service-a",
		OAuthClientSettings: OAuthClientSettings{Name: "Machine", RedirectURIs: []string{}, GrantTypes: []string{"client_credentials"},
			Scopes: []string{"profile", "invoices:read"}, Resources: []string{testAPI}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.provider.RegisterClient(ctx, admin, RegisterOAuthClient{TenantID: "a", ClientID: "spa", Public: true,
		OAuthClientSettings: OAuthClientSettings{Name: "SPA", RedirectURIs: []string{testAPI}}}); err != nil {
		t.Fatal(err)
	}
	listed, err := f.provider.ListClients(ctx, admin, "a", false)
	if err != nil || len(listed) != 2 || listed[0].ClientID != "machine" || listed[1].ClientID != "spa" {
		t.Fatalf("unexpected list %v %v", listed, err)
	}
	machine := listed[0]
	if machine.Name != "Machine" || machine.Public || stringify(anyList(machine.GrantTypes)) != `["client_credentials"]` ||
		stringify(anyList(machine.Scopes)) != `["profile","invoices:read"]` || stringify(anyList(machine.Resources)) != `["`+testAPI+`"]` ||
		machine.ServiceAccountID != "service-a" || machine.RequireDPoP || machine.Revoked || machine.CreatedAt == nil || *machine.CreatedAt <= 0 {
		t.Fatalf("unexpected summary %+v", machine)
	}
	if strings.Contains(stringify(toObject(listed)), registered.ClientSecret) {
		t.Fatal("the secret is listed")
	}
	if other, _ := f.provider.ListClients(ctx, admin, "b", false); len(other) != 0 {
		t.Fatal("expected no clients in b")
	}
	if visible, err := f.provider.ListClients(ctx, member, "a", false); err != nil || len(visible) != 0 {
		t.Fatalf("expected nothing readable, got %v %v", visible, err)
	}
	if !f.wasDenied("iam:oauth:clients:read") {
		t.Fatal("expected a denied read")
	}
	_, err = f.provider.GetClient(ctx, admin, "b", "machine")
	expectIamError(t, err, 404, "")
	_, err = f.provider.RegisterClient(ctx, admin, RegisterOAuthClient{TenantID: "a", ClientID: "x",
		OAuthClientSettings: OAuthClientSettings{Name: "X", RedirectURIs: []string{testAPI}, Resources: []string{"https://unknown.example.test"}}})
	expectIamError(t, err, 0, "INVALID_INPUT")
	issue := func(secret, scope string) *httpResult {
		return f.token(t, form("grant_type", "client_credentials", "scope", scope), map[string]string{"authorization": basicAuth("machine", secret)})
	}
	if response := issue(registered.ClientSecret, "profile"); response.Status != 200 {
		t.Fatalf("issue status %d %s", response.Status, response.Body)
	}
	rotated, err := f.provider.RotateClientSecret(ctx, admin, "a", "machine", false)
	if err != nil || rotated.ClientSecret == registered.ClientSecret {
		t.Fatalf("rotation failed %v %v", rotated, err)
	}
	if issue(registered.ClientSecret, "profile").Status != 401 || issue(rotated.ClientSecret, "profile").Status != 200 {
		t.Fatal("rotation did not replace the secret")
	}
	current, _ := f.provider.GetClient(ctx, admin, "a", "machine")
	if current.SecretRotatedAt == nil || *current.SecretRotatedAt <= 0 {
		t.Fatal("expected secretRotatedAt")
	}
	clients, _ := f.store.Find(ctx, "oauthClients", nil, nil)
	if strings.Contains(stringify(anyObjects(clients)), rotated.ClientSecret) {
		t.Fatal("the rotated secret is stored in clear")
	}
	_, err = f.provider.RotateClientSecret(ctx, admin, "a", "spa", false)
	expectIamError(t, err, 0, "INVALID_INPUT")
	_, err = f.provider.RotateClientSecret(ctx, member, "a", "machine", false)
	expectIamError(t, err, 403, "")
	name := "Billing sync"
	renamed, err := f.provider.UpdateClient(ctx, admin, UpdateOAuthClient{TenantID: "a", ClientID: "machine", Name: &name})
	if err != nil || renamed.Name != "Billing sync" || *renamed.TokensRevoked {
		t.Fatalf("unexpected rename %+v %v", renamed, err)
	}
	if artifacts, _ := f.store.Find(ctx, "oauthArtifacts", core.NewObject("clientId", "machine"), nil); len(artifacts) == 0 {
		t.Fatal("expected artifacts to survive a rename")
	}
	narrowedClient, err := f.provider.UpdateClient(ctx, admin, UpdateOAuthClient{TenantID: "a", ClientID: "machine", Scopes: []string{"invoices:read"}})
	if err != nil || stringify(anyList(narrowedClient.Scopes)) != `["invoices:read"]` || !*narrowedClient.TokensRevoked {
		t.Fatalf("unexpected narrowing %+v %v", narrowedClient, err)
	}
	if artifacts, _ := f.store.Find(ctx, "oauthArtifacts", core.NewObject("clientId", "machine"), nil); len(artifacts) != 0 {
		t.Fatal("expected artifacts purged")
	}
	if response := issue(rotated.ClientSecret, "profile"); response.Status != 400 {
		t.Fatalf("expected a removed scope refused, got %d %s", response.Status, response.Body)
	}
	_, err = f.provider.UpdateClient(ctx, admin, UpdateOAuthClient{TenantID: "a", ClientID: "spa", GrantTypes: []string{"client_credentials"}})
	expectIamError(t, err, 0, "INVALID_INPUT")
	mine := "Mine"
	_, err = f.provider.UpdateClient(ctx, member, UpdateOAuthClient{TenantID: "a", ClientID: "spa", Name: &mine})
	expectIamError(t, err, 403, "")
	if !f.wasDenied("iam:oauth:clients:update") {
		t.Fatal("expected a denied update")
	}
	if err := f.provider.RevokeClient(ctx, admin, "a", "spa"); err != nil {
		t.Fatal(err)
	}
	if remaining, _ := f.provider.ListClients(ctx, admin, "a", false); len(remaining) != 1 || remaining[0].ClientID != "machine" {
		t.Fatalf("unexpected remaining clients %v", remaining)
	}
	all, _ := f.provider.ListClients(ctx, admin, "a", true)
	found := false
	for _, client := range all {
		if client.ClientID == "spa" && client.Revoked {
			found = true
		}
	}
	if !found {
		t.Fatal("expected the revoked client with includeRevoked")
	}
	actions := auditActions(t, f.store, "a")
	for _, action := range []string{"iam:oauth:RegisterClient", "iam:oauth:RotateClientSecret", "iam:oauth:UpdateClient", "iam:oauth:RevokeClient"} {
		if !contains(actions, action) {
			t.Fatalf("missing audit event %s in %v", action, actions)
		}
	}
}

func TestConnectedAppsListAndRevoke(t *testing.T) {
	f := newManagementFixture(t, nil)
	ctx := context.Background()
	member := core.CredentialInput{Token: "member"}
	if _, err := f.provider.RegisterClient(ctx, admin, RegisterOAuthClient{TenantID: "a", ClientID: "web", Public: true,
		OAuthClientSettings: OAuthClientSettings{Name: "Web app", RedirectURIs: []string{f.origin + "/callback"},
			Scopes: []string{"openid", "profile", "email", "offline_access"}, LogoURI: "https://app.example.test/logo.png",
			PolicyURI: "https://app.example.test/privacy", FirstParty: true}}); err != nil {
		t.Fatal(err)
	}
	user := newBrowser(t)
	details, first := f.authorizeFlow(t, user, "web", "openid profile offline_access", nil, nil)
	if str(details, "clientName") != "Web app" || stringify(details.Get("resources")) != "[]" ||
		stringify(details.Get("client")) != `{"name":"Web app","logoUri":"https://app.example.test/logo.png","policyUri":"https://app.example.test/privacy","firstParty":true}` {
		t.Fatalf("unexpected details %s", stringify(details))
	}
	tos := "https://app.example.test/terms"
	branded, err := f.provider.UpdateClient(ctx, admin, UpdateOAuthClient{TenantID: "a", ClientID: "web", RemoveLogoURI: true, TosURI: &tos})
	if err != nil || branded.TosURI != tos || !branded.FirstParty || branded.LogoURI != "" {
		t.Fatalf("unexpected branding %+v %v", branded, err)
	}
	insecure := "http://app.example.test"
	_, err = f.provider.UpdateClient(ctx, admin, UpdateOAuthClient{TenantID: "a", ClientID: "web", ClientURI: &insecure})
	expectIamError(t, err, 0, "INVALID_INPUT")
	grants, err := f.provider.ListGrants(ctx, member, "a", "", "")
	if err != nil || len(grants) != 1 || grants[0].TenantID != "a" || grants[0].IdentityID != "user-a" || grants[0].ClientID != "web" ||
		grants[0].ClientName != "Web app" || !contains(grants[0].Scopes, "openid") || !contains(grants[0].Scopes, "profile") || grants[0].CreatedAt <= 0 {
		t.Fatalf("unexpected grants %+v %v", grants, err)
	}
	f.authorizeFlow(t, user, "web", "openid profile email offline_access", nil, nil)
	grants, _ = f.provider.ListGrants(ctx, member, "a", "", "")
	if len(grants) != 1 || !contains(grants[0].Scopes, "email") {
		t.Fatalf("expected one extended grant, got %+v", grants)
	}
	_, err = f.provider.ListGrants(ctx, member, "a", "user-a2", "")
	expectIamError(t, err, 403, "")
	if !f.wasDenied("iam:oauth:grants:read") {
		t.Fatal("expected a denied grants read")
	}
	if others, err := f.provider.ListGrants(ctx, admin, "a", "user-a2", ""); err != nil || len(others) != 0 {
		t.Fatalf("unexpected grants of user-a2 %v %v", others, err)
	}
	_, err = f.provider.ListGrants(ctx, admin, "b", "user-a", "")
	expectIamError(t, err, 404, "")
	err = f.provider.RevokeGrant(ctx, member, "a", strings.Repeat("f", 64))
	expectIamError(t, err, 404, "")
	if err := f.provider.RevokeGrant(ctx, member, "a", grants[0].ID); err != nil {
		t.Fatal(err)
	}
	if left, _ := f.provider.ListGrants(ctx, member, "a", "", ""); len(left) != 0 {
		t.Fatalf("expected no grants, got %v", left)
	}
	refused := f.token(t, form("grant_type", "refresh_token", "client_id", "web", "refresh_token", str(first, "refresh_token")), nil)
	if refused.Status != 400 || str(refused.JSON(t), "error") != "invalid_grant" {
		t.Fatalf("expected invalid_grant, got %d %s", refused.Status, refused.Body)
	}
	_, second := f.authorizeFlow(t, newBrowser(t), "web", "openid offline_access", nil, nil)
	if left, _ := f.provider.ListGrants(ctx, member, "a", "", ""); len(left) != 1 {
		t.Fatalf("expected one grant, got %v", left)
	}
	if count, err := f.provider.RevokeGrants(ctx, member, "a", "", "other"); err != nil || count != 0 {
		t.Fatalf("expected nothing revoked, got %d %v", count, err)
	}
	if count, err := f.provider.RevokeGrants(ctx, member, "a", "", "web"); err != nil || count != 1 {
		t.Fatalf("expected one revoked, got %d %v", count, err)
	}
	if response := f.token(t, form("grant_type", "refresh_token", "client_id", "web", "refresh_token", str(second, "refresh_token")), nil); response.Status != 400 {
		t.Fatalf("expected the refresh refused, got %d", response.Status)
	}
	if count := countOf(auditActions(t, f.store, "a"), "iam:oauth:RevokeGrant"); count != 2 {
		t.Fatalf("expected two RevokeGrant events, got %d", count)
	}
}

func jwtLifetime(t *testing.T, token string) float64 {
	claims := decodePayload(t, token)
	exp, _ := num(claims, "exp")
	iat, _ := num(claims, "iat")
	return exp - iat
}

func TestAudienceRestrictedJWTAccessTokens(t *testing.T) {
	f := newManagementFixture(t, nil)
	ctx := context.Background()
	machine, err := f.provider.RegisterClient(ctx, admin, RegisterOAuthClient{TenantID: "a", ClientID: "machine", ServiceAccountID: "service-a",
		OAuthClientSettings: OAuthClientSettings{Name: "Machine", RedirectURIs: []string{}, GrantTypes: []string{"client_credentials"},
			Scopes: []string{"invoices:read"}, Resources: []string{testAPI}}})
	if err != nil {
		t.Fatal(err)
	}
	authHeader := map[string]string{"authorization": basicAuth("machine", machine.ClientSecret)}
	response := f.token(t, form("grant_type", "client_credentials", "scope", "invoices:read", "resource", testAPI), authHeader)
	if response.Status != 200 {
		t.Fatalf("token status %d %s", response.Status, response.Body)
	}
	issued := response.JSON(t)
	accessToken := str(issued, "access_token")
	if str(issued, "token_type") != "Bearer" || len(strings.Split(accessToken, ".")) != 3 {
		t.Fatalf("unexpected token %s", response.Body)
	}
	verifier, err := CreateAccessTokenVerifier(AccessTokenVerifierOptions{Issuer: f.origin + "/oidc", Audience: []string{testAPI}})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifier.Verify(ctx, accessToken, []string{"invoices:read"})
	if err != nil || verified.ClientID != "machine" || verified.TenantID != "a" || verified.IdentityID != "service-a" ||
		stringify(anyList(verified.Scopes)) != `["invoices:read"]` || stringify(anyList(verified.Audience)) != `["`+testAPI+`"]` || verified.BoundKey != "" {
		t.Fatalf("unexpected verification %+v %v", verified, err)
	}
	_, err = verifier.Verify(ctx, accessToken, []string{"invoices:write"})
	expectIamError(t, err, 403, "INSUFFICIENT_SCOPE")
	_, public := testRSAKey()
	elsewhere, _ := CreateAccessTokenVerifier(AccessTokenVerifierOptions{Issuer: f.origin + "/oidc", Audience: []string{"https://other.example.test"},
		JWKS: core.NewObject("keys", []any{public})})
	_, err = elsewhere.Verify(ctx, accessToken, nil)
	expectIamError(t, err, 401, "")
	_, err = verifier.Verify(ctx, accessToken+"x", nil)
	expectIamError(t, err, 0, "INVALID_TOKEN")
	if challenge := verifier.Challenge(core.NewIamError("INSUFFICIENT_SCOPE", "x", 403), "api", "", nil); !strings.Contains(challenge, `error="insufficient_scope"`) {
		t.Fatalf("unexpected challenge %s", challenge)
	}
	if lifetime := jwtLifetime(t, accessToken); lifetime != 900 {
		t.Fatalf("expected 900 seconds, got %v", lifetime)
	}
	updated, err := f.provider.UpdateClient(ctx, admin, UpdateOAuthClient{TenantID: "a", ClientID: "machine", AccessTokenTTL: int64Ptr(120), RefreshTokenTTL: int64Ptr(3600)})
	if err != nil || *updated.AccessTokenTTL != 120 || *updated.RefreshTokenTTL != 3600 || *updated.TokensRevoked {
		t.Fatalf("unexpected lifetimes %+v %v", updated, err)
	}
	shorter := f.token(t, form("grant_type", "client_credentials", "scope", "invoices:read", "resource", testAPI), authHeader).JSON(t)
	if lifetime := jwtLifetime(t, str(shorter, "access_token")); lifetime != 120 {
		t.Fatalf("expected 120 seconds, got %v", lifetime)
	}
	cleared, err := f.provider.UpdateClient(ctx, admin, UpdateOAuthClient{TenantID: "a", ClientID: "machine", RemoveAccessTokenTTL: true})
	if err != nil || cleared.AccessTokenTTL != nil {
		t.Fatalf("expected the lifetime cleared %+v %v", cleared, err)
	}
	_, err = f.provider.UpdateClient(ctx, admin, UpdateOAuthClient{TenantID: "a", ClientID: "machine", AccessTokenTTL: int64Ptr(5)})
	expectIamError(t, err, 0, "INVALID_INPUT")
	other, err := f.provider.RegisterClient(ctx, admin, RegisterOAuthClient{TenantID: "a", ClientID: "other", ServiceAccountID: "service-a",
		OAuthClientSettings: OAuthClientSettings{Name: "Other", RedirectURIs: []string{}, GrantTypes: []string{"client_credentials"}, Scopes: []string{"invoices:read"}}})
	if err != nil {
		t.Fatal(err)
	}
	refused := f.token(t, form("grant_type", "client_credentials", "scope", "invoices:read", "resource", testAPI), map[string]string{"authorization": basicAuth("other", other.ClientSecret)})
	if refused.Status != 400 || str(refused.JSON(t), "error") != "invalid_target" {
		t.Fatalf("expected invalid_target, got %d %s", refused.Status, refused.Body)
	}
}

func TestResourceServerAccessTokenLifetime(t *testing.T) {
	f := newManagementFixture(t, func(config *OAuthProviderConfig) {
		config.ResourceServers = map[string]OAuthResourceServer{testAPI: {Scopes: []string{"invoices:read"}, AccessTokenTTL: int64Ptr(300)}}
	})
	client, err := f.provider.RegisterClient(context.Background(), admin, RegisterOAuthClient{TenantID: "a", ClientID: "machine", ServiceAccountID: "service-a",
		OAuthClientSettings: OAuthClientSettings{Name: "Machine", RedirectURIs: []string{}, GrantTypes: []string{"client_credentials"},
			Scopes: []string{"invoices:read"}, Resources: []string{testAPI}}})
	if err != nil {
		t.Fatal(err)
	}
	issued := f.token(t, form("grant_type", "client_credentials", "scope", "invoices:read", "resource", testAPI), map[string]string{"authorization": basicAuth("machine", client.ClientSecret)}).JSON(t)
	if jwtLifetime(t, str(issued, "access_token")) != 300 || issued.Get("expires_in") != float64(300) {
		t.Fatalf("unexpected lifetime %s", stringify(issued))
	}
}

// dpopSigner signs DPoP proofs with an ephemeral ES256 key.
func dpopSigner(t *testing.T) func(htm, htu, accessToken string) string {
	private, public := testECKey("")
	return func(htm, htu, accessToken string) string {
		payload := core.NewObject("htm", htm, "htu", htu, "jti", randomUUID())
		if accessToken != "" {
			payload.Set("ath", sha256B64URL(accessToken))
		}
		payload.Set("iat", epoch(wallNow()))
		return signJWT(t, private, "ES256", core.NewObject("typ", "dpop+jwt", "jwk", public), payload)
	}
}

func TestDPoPBoundTokens(t *testing.T) {
	f := newManagementFixture(t, nil)
	ctx := context.Background()
	bound, err := f.provider.RegisterClient(ctx, admin, RegisterOAuthClient{TenantID: "a", ClientID: "bound", ServiceAccountID: "service-a",
		OAuthClientSettings: OAuthClientSettings{Name: "Bound", RedirectURIs: []string{}, GrantTypes: []string{"client_credentials"},
			Scopes: []string{"invoices:read"}, Resources: []string{testAPI}, RequireDPoP: true}})
	if err != nil {
		t.Fatal(err)
	}
	authHeader := map[string]string{"authorization": basicAuth("bound", bound.ClientSecret)}
	body := form("grant_type", "client_credentials", "scope", "invoices:read", "resource", testAPI)
	if response := f.token(t, body, authHeader); response.Status != 400 {
		t.Fatalf("expected a refusal without a proof, got %d %s", response.Status, response.Body)
	}
	proof := dpopSigner(t)
	response := f.token(t, body, map[string]string{"authorization": basicAuth("bound", bound.ClientSecret), "dpop": proof("POST", f.origin+"/oidc/token", "")})
	if response.Status != 200 {
		t.Fatalf("token status %d %s", response.Status, response.Body)
	}
	issued := response.JSON(t)
	if str(issued, "token_type") != "DPoP" {
		t.Fatalf("expected a DPoP token, got %s", response.Body)
	}
	accessToken := str(issued, "access_token")
	_, public := testRSAKey()
	verifier, _ := CreateAccessTokenVerifier(AccessTokenVerifierOptions{Issuer: f.origin + "/oidc", Audience: []string{testAPI}, JWKS: core.NewObject("keys", []any{public})})
	_, err = verifier.Verify(ctx, accessToken, nil)
	expectIamError(t, err, 401, "")
	request := func(dpop, scheme string) error {
		_, err := verifier.VerifyRequest(ctx, ProtectedRequest{Authorization: scheme + " " + accessToken, DPoP: dpop, Method: "get", URL: testAPI + "/invoices?page=2"}, nil)
		return err
	}
	presented := proof("GET", testAPI+"/invoices", accessToken)
	verified, err := verifier.VerifyRequest(ctx, ProtectedRequest{Authorization: "DPoP " + accessToken, DPoP: presented, Method: "get", URL: testAPI + "/invoices?page=2"}, nil)
	if err != nil || verified.BoundKey == "" || verified.ClientID != "bound" {
		t.Fatalf("unexpected verification %+v %v", verified, err)
	}
	expectIamError(t, request(presented, "DPoP"), 401, "")
	expectIamError(t, request(proof("POST", testAPI+"/invoices", accessToken), "DPoP"), 401, "")
	expectIamError(t, request(dpopSigner(t)("GET", testAPI+"/invoices", accessToken), "DPoP"), 401, "")
	expectIamError(t, request(proof("GET", testAPI+"/invoices", accessToken), "Bearer"), 401, "")
	expectIamError(t, request("", "DPoP"), 401, "")
	off, on := false, true
	if _, err := f.provider.UpdateClient(ctx, admin, UpdateOAuthClient{TenantID: "a", ClientID: "bound", RequireDPoP: &off}); err != nil {
		t.Fatal(err)
	}
	updated, err := f.provider.UpdateClient(ctx, admin, UpdateOAuthClient{TenantID: "a", ClientID: "bound", RequireDPoP: &on})
	if err != nil || !*updated.TokensRevoked {
		t.Fatalf("expected tokens revoked when DPoP becomes required %+v %v", updated, err)
	}
}

func TestPushedAuthorizationRequests(t *testing.T) {
	f := newManagementFixture(t, nil)
	ctx := context.Background()
	discovery := fetch(t, "GET", f.origin+"/oidc/.well-known/openid-configuration", nil, "").JSON(t)
	if str(discovery, "pushed_authorization_request_endpoint") != f.origin+"/oidc/request" || !contains(stringList(discovery.Get("dpop_signing_alg_values_supported")), "ES256") {
		t.Fatalf("unexpected discovery %s", stringify(discovery))
	}
	if _, err := f.provider.RegisterClient(ctx, admin, RegisterOAuthClient{TenantID: "a", ClientID: "par", Public: true,
		OAuthClientSettings: OAuthClientSettings{Name: "PAR", RedirectURIs: []string{f.origin + "/callback"}, RequirePushedAuthorization: true}}); err != nil {
		t.Fatal(err)
	}
	params := form("client_id", "par", "response_type", "code", "redirect_uri", f.origin+"/callback", "scope", "openid",
		"code_challenge", sha256B64URL("verifier"), "code_challenge_method", "S256")
	direct := fetch(t, "GET", f.origin+"/oidc/auth?"+params, nil, "")
	if direct.Status != 303 || !strings.Contains(direct.Header.Get("location"), "error=invalid_request") {
		t.Fatalf("expected a PAR requirement refusal, got %d %s", direct.Status, direct.Header.Get("location"))
	}
	pushed := fetch(t, "POST", f.origin+"/oidc/request", map[string]string{"content-type": formType}, params)
	if pushed.Status != 201 {
		t.Fatalf("PAR status %d %s", pushed.Status, pushed.Body)
	}
	requestURI := str(pushed.JSON(t), "request_uri")
	if !strings.HasPrefix(requestURI, "urn:ietf:params:oauth:request_uri:") {
		t.Fatalf("unexpected request_uri %s", requestURI)
	}
	viaPar := fetch(t, "GET", f.origin+"/oidc/auth?"+form("client_id", "par", "request_uri", requestURI), nil, "")
	if viaPar.Status != 303 || !strings.Contains(viaPar.Header.Get("location"), "/interactions/") {
		t.Fatalf("expected an interaction, got %d %s %s", viaPar.Status, viaPar.Header.Get("location"), viaPar.Body)
	}
	if client, _ := f.provider.GetClient(ctx, admin, "a", "par"); !client.RequirePushedAuthorization {
		t.Fatal("expected requirePushedAuthorization")
	}
}

func TestPrivateKeyJWTClientAuthentication(t *testing.T) {
	f := newManagementFixture(t, nil)
	ctx := context.Background()
	firstPrivate, firstPublic := testECKey("")
	secondPrivate, secondPublic := testECKey("")
	jwk := func(public *core.Object, kid string) *core.Object {
		out := public.Clone()
		out.Set("kid", kid)
		out.Set("alg", "ES256")
		out.Set("use", "sig")
		return out
	}
	registered, err := f.provider.RegisterClient(ctx, admin, RegisterOAuthClient{TenantID: "a", ClientID: "signed", ServiceAccountID: "service-a",
		TokenEndpointAuthMethod: "private_key_jwt", OAuthClientSettings: OAuthClientSettings{Name: "Signed", RedirectURIs: []string{},
			GrantTypes: []string{"client_credentials"}, Scopes: []string{"profile"}, JWKS: core.NewObject("keys", []any{jwk(firstPublic, "one")})}})
	if err != nil {
		t.Fatal(err)
	}
	if registered.ClientSecret != "" {
		t.Fatal("expected no secret")
	}
	if summary, _ := f.provider.GetClient(ctx, admin, "a", "signed"); summary.TokenEndpointAuthMethod != "private_key_jwt" || stringify(anyList(summary.KeyIDs)) != `["one"]` {
		t.Fatalf("unexpected summary %+v", summary)
	}
	assertion := func(private *core.Object, kid string) string {
		now := epoch(wallNow())
		return signJWT(t, private, "ES256", core.NewObject("kid", kid), core.NewObject("jti", randomUUID(), "iss", "signed",
			"sub", "signed", "aud", f.origin+"/oidc", "iat", now, "exp", now+60))
	}
	exchange := func(clientAssertion string) *httpResult {
		return f.token(t, form("grant_type", "client_credentials", "scope", "profile", "client_id", "signed",
			"client_assertion_type", assertionType, "client_assertion", clientAssertion), nil)
	}
	signed := assertion(firstPrivate, "one")
	if response := exchange(signed); response.Status != 200 {
		t.Fatalf("assertion status %d %s", response.Status, response.Body)
	}
	if exchange(signed).Status != 401 {
		t.Fatal("expected a replayed assertion refused")
	}
	if exchange(assertion(secondPrivate, "one")).Status != 401 {
		t.Fatal("expected a foreign key refused")
	}
	rotated, err := f.provider.UpdateClient(ctx, admin, UpdateOAuthClient{TenantID: "a", ClientID: "signed", JWKS: core.NewObject("keys", []any{jwk(secondPublic, "two")})})
	if err != nil || stringify(anyList(rotated.KeyIDs)) != `["two"]` || *rotated.TokensRevoked {
		t.Fatalf("unexpected rotation %+v %v", rotated, err)
	}
	if response := exchange(assertion(secondPrivate, "two")); response.Status != 200 {
		t.Fatalf("new key status %d %s", response.Status, response.Body)
	}
	if exchange(assertion(firstPrivate, "one")).Status != 401 {
		t.Fatal("expected the retired key refused")
	}
	_, err = f.provider.RotateClientSecret(ctx, admin, "a", "signed", false)
	expectIamError(t, err, 0, "INVALID_INPUT")
	base := func(id string) RegisterOAuthClient {
		return RegisterOAuthClient{TenantID: "a", ClientID: id, ServiceAccountID: "service-a", TokenEndpointAuthMethod: "private_key_jwt",
			OAuthClientSettings: OAuthClientSettings{Name: "Bad", RedirectURIs: []string{}, GrantTypes: []string{"client_credentials"}}}
	}
	privateKey := base("private")
	withKid := firstPrivate.Clone()
	withKid.Set("kid", "x")
	privateKey.JWKS = core.NewObject("keys", []any{withKid})
	_, err = f.provider.RegisterClient(ctx, admin, privateKey)
	expectIamError(t, err, 0, "INVALID_INPUT")
	_, err = f.provider.RegisterClient(ctx, admin, base("keyless"))
	expectIamError(t, err, 0, "INVALID_INPUT")
	secretWithKeys := base("secret-with-keys")
	secretWithKeys.TokenEndpointAuthMethod = "client_secret_basic"
	secretWithKeys.JWKS = core.NewObject("keys", []any{jwk(firstPublic, "one")})
	_, err = f.provider.RegisterClient(ctx, admin, secretWithKeys)
	expectIamError(t, err, 0, "INVALID_INPUT")
	insecure := base("insecure")
	insecure.JWKSURI = "http://keys.example.test/jwks"
	_, err = f.provider.RegisterClient(ctx, admin, insecure)
	expectIamError(t, err, 0, "INVALID_INPUT")
}

func TestBackchannelLogoutAndEndedSessions(t *testing.T) {
	var mu sync.Mutex
	var received []string
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		values, _ := url.ParseQuery(string(raw))
		mu.Lock()
		received = append(received, values.Get("logout_token"))
		mu.Unlock()
		if r.URL.Path == "/fail" {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(204)
	}))
	defer receiver.Close()
	f := newManagementFixture(t, nil)
	ctx := context.Background()
	member := core.CredentialInput{Token: "member"}
	for _, pair := range [][2]string{{"web", "/logout"}, {"flaky", "/fail"}} {
		if _, err := f.provider.RegisterClient(ctx, admin, RegisterOAuthClient{TenantID: "a", ClientID: pair[0], Public: true,
			OAuthClientSettings: OAuthClientSettings{Name: pair[0], RedirectURIs: []string{f.origin + "/callback"},
				Scopes: []string{"openid", "offline_access"}, BackchannelLogoutURI: receiver.URL + pair[1]}}); err != nil {
			t.Fatal(err)
		}
	}
	if client, _ := f.provider.GetClient(ctx, admin, "a", "web"); client.BackchannelLogoutURI != receiver.URL+"/logout" {
		t.Fatalf("unexpected backchannel URI %s", client.BackchannelLogoutURI)
	}
	user := newBrowser(t)
	_, web := f.authorizeFlow(t, user, "web", "openid offline_access", nil, nil)
	f.authorizeFlow(t, user, "flaky", "openid offline_access", nil, nil)
	if grants, _ := f.provider.ListGrants(ctx, member, "a", "", ""); len(grants) != 2 {
		t.Fatalf("expected two grants, got %d", len(grants))
	}
	if result, err := f.provider.LogoutEndedSessions(ctx, ""); err != nil || stringify(toObject(result)) != `{"sessions":0,"grants":0,"notified":0,"failures":[]}` {
		t.Fatalf("unexpected sweep %v %v", result, err)
	}
	remove(t, f.store, "sessions", "session-a")
	result, err := f.provider.LogoutEndedSessions(ctx, "user-a")
	if err != nil || stringify(toObject(result)) != `{"sessions":1,"grants":2,"notified":1,"failures":[{"clientId":"flaky","identityId":"user-a"}]}` {
		t.Fatalf("unexpected sweep %s %v", stringify(toObject(result)), err)
	}
	if len(received) != 2 {
		t.Fatalf("expected two logout tokens, got %d", len(received))
	}
	logout := decodePayload(t, received[0])
	if str(logout, "iss") != f.origin+"/oidc" || str(logout, "sub") != "user-a" ||
		stringify(logout.Get("events")) != `{"http://schemas.openid.net/event/backchannel-logout":{}}` ||
		!contains([]string{"web", "flaky"}, str(logout, "aud")) || logout.Has("nonce") {
		t.Fatalf("unexpected logout token %s", stringify(logout))
	}
	now := wallNow()
	insert(t, f.store, "sessions", core.NewObject("id", "session-a", "tenantId", "a", "identityId", "user-a", "kind", "user", "tokenHash", "irrelevant",
		"createdAt", now, "authenticatedAt", now, "lastSeenAt", now, "expiresAt", now+100000, "mfa", true))
	if grants, _ := f.provider.ListGrants(ctx, member, "a", "", ""); len(grants) != 0 {
		t.Fatalf("expected no grants, got %d", len(grants))
	}
	if response := f.token(t, form("grant_type", "refresh_token", "client_id", "web", "refresh_token", str(web, "refresh_token")), nil); response.Status != 400 {
		t.Fatalf("expected the refresh refused, got %d", response.Status)
	}
	if again, _ := f.provider.LogoutEndedSessions(ctx, ""); again.Sessions != 0 {
		t.Fatalf("expected nothing left, got %+v", again)
	}
	if _, err := f.provider.UpdateClient(ctx, admin, UpdateOAuthClient{TenantID: "a", ClientID: "web", RemoveBackchannelLogoutURI: true}); err != nil {
		t.Fatal(err)
	}
	if client, _ := f.provider.GetClient(ctx, admin, "a", "web"); client.BackchannelLogoutURI != "" {
		t.Fatal("expected the backchannel URI removed")
	}
}

func TestTokenExchange(t *testing.T) {
	const reports = "https://reports.example.test"
	var mu sync.Mutex
	refused := map[string]bool{}
	f := newManagementFixture(t, func(config *OAuthProviderConfig) {
		config.ResourceServers = map[string]OAuthResourceServer{testAPI: {Scopes: []string{"invoices:read"}}, reports: {Scopes: []string{"reports:read", "reports:write"}}}
		config.AuthorizeTokenExchange = func(_ context.Context, request TokenExchangeRequest) (bool, error) {
			mu.Lock()
			defer mu.Unlock()
			return !refused[request.SubjectClientID], nil
		}
	})
	ctx := context.Background()
	if _, err := f.provider.RegisterClient(ctx, admin, RegisterOAuthClient{TenantID: "a", ClientID: "web", Public: true,
		OAuthClientSettings: OAuthClientSettings{Name: "Web", RedirectURIs: []string{f.origin + "/callback"}, Scopes: []string{"openid", "invoices:read"}, Resources: []string{testAPI}}}); err != nil {
		t.Fatal(err)
	}
	gateway, err := f.provider.RegisterClient(ctx, admin, RegisterOAuthClient{TenantID: "a", ClientID: "gateway",
		OAuthClientSettings: OAuthClientSettings{Name: "Invoice API", RedirectURIs: []string{}, GrantTypes: []string{tokenExchangeGrant},
			Scopes: []string{"reports:read"}, Resources: []string{reports}}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.provider.RegisterClient(ctx, admin, RegisterOAuthClient{TenantID: "a", ClientID: "public-exchange", Public: true,
		OAuthClientSettings: OAuthClientSettings{Name: "X", RedirectURIs: []string{}, GrantTypes: []string{tokenExchangeGrant}}})
	expectIamError(t, err, 0, "INVALID_INPUT")
	discovery := fetch(t, "GET", f.origin+"/oidc/.well-known/openid-configuration", nil, "").JSON(t)
	if !contains(stringList(discovery.Get("grant_types_supported")), tokenExchangeGrant) {
		t.Fatal("token exchange not advertised")
	}
	_, tokens := f.authorizeFlow(t, newBrowser(t), "web", "openid invoices:read", []string{"resource", testAPI}, []string{"resource", testAPI})
	subject := str(tokens, "access_token")
	if len(strings.Split(subject, ".")) != 3 {
		t.Fatalf("expected a JWT subject token, got %s", subject)
	}
	exchange := func(pairs ...string) *httpResult {
		return f.token(t, form(append([]string{"grant_type", tokenExchangeGrant, "subject_token_type", accessTokenType}, pairs...)...),
			map[string]string{"authorization": basicAuth("gateway", gateway.ClientSecret)})
	}
	response := exchange("subject_token", subject, "resource", reports)
	if response.Status != 200 {
		t.Fatalf("exchange status %d %s", response.Status, response.Body)
	}
	exchanged := response.JSON(t)
	if str(exchanged, "issued_token_type") != accessTokenType || str(exchanged, "token_type") != "Bearer" || str(exchanged, "scope") != "reports:read" {
		t.Fatalf("unexpected exchange %s", response.Body)
	}
	_, public := testRSAKey()
	verifier, _ := CreateAccessTokenVerifier(AccessTokenVerifierOptions{Issuer: f.origin + "/oidc", Audience: []string{reports}, JWKS: core.NewObject("keys", []any{public})})
	verified, err := verifier.Verify(ctx, str(exchanged, "access_token"), []string{"reports:read"})
	if err != nil || verified.Subject != "user-a" || verified.ClientID != "gateway" || verified.TenantID != "a" ||
		verified.Actor == nil || str(verified.Actor, "sub") != "gateway" || verified.IdentityID != "" {
		t.Fatalf("unexpected verification %+v %v", verified, err)
	}
	subjectExp, _ := num(decodePayload(t, subject), "exp")
	if verified.ExpiresAt > subjectExp {
		t.Fatal("the exchanged token outlives its subject token")
	}
	chained := exchange("subject_token", str(exchanged, "access_token"), "resource", reports).JSON(t)
	if act := stringify(decodePayload(t, str(chained, "access_token")).Get("act")); act != `{"sub":"gateway","act":{"sub":"gateway"}}` {
		t.Fatalf("unexpected chained actor %s", act)
	}
	_, plain := f.authorizeFlow(t, newBrowser(t), "web", "openid", nil, nil)
	if response := exchange("subject_token", str(plain, "access_token"), "audience", reports); response.Status != 200 {
		t.Fatalf("opaque exchange status %d %s", response.Status, response.Body)
	}
	failure := func(pairs ...string) string {
		result := exchange(pairs...)
		return itoa(result.Status) + " " + str(result.JSON(t), "error")
	}
	if got := failure("subject_token", subject, "resource", reports, "scope", "reports:write"); got != "400 invalid_scope" {
		t.Fatalf("unexpected %s", got)
	}
	if got := failure("subject_token", subject, "resource", testAPI); got != "400 invalid_target" {
		t.Fatalf("unexpected %s", got)
	}
	if got := failure("subject_token", "not-a-token", "resource", reports); got != "400 invalid_grant" {
		t.Fatalf("unexpected %s", got)
	}
	if got := failure("subject_token", subject, "resource", reports, "actor_token", "x", "actor_token_type", accessTokenType); got != "400 invalid_request" {
		t.Fatalf("unexpected %s", got)
	}
	mu.Lock()
	refused["web"] = true
	mu.Unlock()
	if got := failure("subject_token", subject, "resource", reports); got != "400 access_denied" {
		t.Fatalf("unexpected %s", got)
	}
	mu.Lock()
	delete(refused, "web")
	mu.Unlock()
	update(t, f.store, "identities", "user-a", func(record *core.Object) { record.Set("status", "disabled") })
	if got := failure("subject_token", subject, "resource", reports); got != "400 invalid_grant" {
		t.Fatalf("unexpected %s", got)
	}
	if count := countOf(auditActions(t, f.store, "a"), "iam:oauth:TokenExchange"); count != 3 {
		t.Fatalf("expected three TokenExchange events, got %d", count)
	}
}

func TestInvalidResourceServerConfiguration(t *testing.T) {
	store := newTestStore(t)
	signing, _ := testRSAKey()
	base := func() OAuthProviderConfig {
		return OAuthProviderConfig{Store: store, Issuer: "https://issuer.example.test", JWKS: core.NewObject("keys", []any{signing}),
			EncryptionKey: randomKey(), CookieKeys: []string{"test-key-with-at-least-32-characters-long"}, TrustedOrigins: []string{"https://issuer.example.test"},
			Authenticate:     func(context.Context, core.CredentialInput) (*auth.Principal, error) { return nil, core.NewIamError("X", "unused") },
			Authorize:        func(context.Context, core.CredentialInput, string, core.ResourceRef) error { return nil },
			InteractionURL:   func(uid string) string { return uid },
			RenderDevicePage: func(context.Context, DevicePageInput) (string, error) { return "", nil },
			RenderLogoutPage: func(context.Context, string) (string, error) { return "", nil }}
	}
	check := func(configure func(config *OAuthProviderConfig), pattern string) {
		t.Helper()
		config := base()
		configure(&config)
		_, err := CreateOAuthProvider(config)
		if err == nil || !strings.Contains(err.Error(), pattern) {
			t.Fatalf("expected %q, got %v", pattern, err)
		}
	}
	check(func(c *OAuthProviderConfig) {
		c.ResourceServers = map[string]OAuthResourceServer{"not a uri": {Scopes: []string{"a"}}}
	}, "absolute URIs")
	check(func(c *OAuthProviderConfig) {
		c.ResourceServers = map[string]OAuthResourceServer{testAPI + "#x": {Scopes: []string{"a"}}}
	}, "fragment")
	check(func(c *OAuthProviderConfig) { c.ResourceServers = map[string]OAuthResourceServer{testAPI: {Scopes: []string{}}} }, "scope identifiers")
	check(func(c *OAuthProviderConfig) { c.DPoPNonceSecret = "short" }, "32 bytes")
}
