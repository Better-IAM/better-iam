package oauth

// Port of tests/oauth.test.ts.

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

func seedOAuthTenants(t *testing.T, store core.IamStore) {
	t.Helper()
	now := wallNow()
	for _, id := range []string{"root", "a", "b"} {
		tenant := core.NewObject("id", id, "tenantId", id, "name", id, "type", "organization", "parentId", "root", "status", "active", "createdAt", now)
		if id == "root" {
			tenant.Set("type", "root")
			tenant.Set("parentId", nil)
		}
		insert(t, store, "tenants", tenant)
	}
	for _, id := range []string{"a", "b"} {
		insert(t, store, "identities", core.NewObject("id", "user-"+id, "tenantId", id, "name", id, "kind", "user", "emailVerified", true,
			"email", "same@example.test", "status", "active", "rootAdmin", false, "owner", false, "createdAt", now))
	}
	insert(t, store, "identities", core.NewObject("id", "service-a", "tenantId", "a", "name", "Service A", "kind", "service",
		"emailVerified", false, "status", "active", "rootAdmin", false, "owner", false, "createdAt", now))
	update(t, store, "identities", "user-a", func(record *core.Object) {
		record.Set("attributes", core.NewObject("department", "finance"))
	})
	insert(t, store, "groupMembers", core.NewObject("id", "member-a", "tenantId", "a", "groupId", "group-a", "identityId", "user-a"))
	insert(t, store, "bindings", core.NewObject("id", "binding-direct", "tenantId", "a", "subjectType", "identity", "subjectId", "user-a", "roleId", "role-direct", "authorityId", "authority-a"))
	insert(t, store, "bindings", core.NewObject("id", "binding-group", "tenantId", "a", "subjectType", "group", "subjectId", "group-a", "roleId", "role-group", "authorityId", "authority-a"))
	insert(t, store, "bindings", core.NewObject("id", "binding-expired", "tenantId", "a", "subjectType", "identity", "subjectId", "user-a", "roleId", "role-expired", "authorityId", "authority-a", "expiresAt", now-1000))
	insert(t, store, "identities", core.NewObject("id", "service-b", "tenantId", "b", "name", "Service B", "kind", "service",
		"emailVerified", false, "status", "active", "rootAdmin", false, "owner", false, "createdAt", now))
}

type oauthFixture struct {
	store     core.IamStore
	server    *providerServer
	provider  *Provider
	origin    string
	key       string
	principal *auth.Principal
}

func newOAuthFixture(t *testing.T, configure func(config *OAuthProviderConfig)) *oauthFixture {
	t.Helper()
	store := newTestStore(t)
	seedOAuthTenants(t, store)
	server := newProviderServer(t)
	origin := server.URL
	identity, _ := store.Get(context.Background(), "identities", "user-a")
	now := wallNow()
	session := core.NewObject("id", "session-a", "tenantId", "a", "identityId", "user-a", "kind", "user", "tokenHash", "irrelevant",
		"createdAt", now, "authenticatedAt", now, "lastSeenAt", now, "expiresAt", now+100000, "mfa", true)
	insert(t, store, "sessions", session)
	principal := &auth.Principal{Identity: identity, Session: session}
	signing, _ := testRSAKey()
	key := randomKey()
	config := OAuthProviderConfig{
		Store: store, Issuer: origin + "/oidc", JWKS: core.NewObject("keys", []any{signing}), EncryptionKey: key,
		CookieKeys: []string{"test-key-with-at-least-32-characters-long"}, TrustedOrigins: []string{origin}, AllowInsecureLocalhost: true,
		Authenticate: staticPrincipal("admin", func() *auth.Principal { return principal }),
		Authorize: func(_ context.Context, credential core.CredentialInput, _ string, _ core.ResourceRef) error {
			if credential.Token != "admin" {
				return core.NewIamError("FORBIDDEN", "Forbidden", 403)
			}
			return nil
		},
		InteractionURL: func(uid string) string { return origin + "/interactions/" + uid },
		RenderDevicePage: func(_ context.Context, input DevicePageInput) (string, error) {
			return "<html><body>" + input.Form + "</body></html>", nil
		},
		RenderLogoutPage: func(_ context.Context, form string) (string, error) {
			return "<html><body>" + form + "</body></html>", nil
		},
	}
	if configure != nil {
		configure(&config)
	}
	provider, err := CreateOAuthProvider(config)
	if err != nil {
		t.Fatal(err)
	}
	server.provider = provider
	return &oauthFixture{store: store, server: server, provider: provider, origin: origin, key: key, principal: principal}
}

var admin = core.CredentialInput{Token: "admin"}

func TestDiscoveryAndPKCEOnlyAuthorization(t *testing.T) {
	f := newOAuthFixture(t, nil)
	ctx := context.Background()
	discoveryResponse := fetch(t, "GET", f.origin+"/oidc/.well-known/openid-configuration", nil, "")
	if discoveryResponse.Status != 200 {
		t.Fatalf("discovery status %d", discoveryResponse.Status)
	}
	discovery := discoveryResponse.JSON(t)
	if str(discovery, "issuer") != f.origin+"/oidc" || str(discovery, "authorization_endpoint") != f.origin+"/oidc/auth" ||
		str(discovery, "token_endpoint") != f.origin+"/oidc/token" {
		t.Fatalf("unexpected discovery %s", discoveryResponse.Body)
	}
	if !contains(stringList(discovery.Get("grant_types_supported")), deviceCodeGrant) || stringify(discovery.Get("response_types_supported")) != `["code"]` {
		t.Fatalf("unexpected discovery %s", discoveryResponse.Body)
	}
	if discovery.Has("registration_endpoint") {
		t.Fatal("registration endpoint advertised while closed")
	}
	if _, err := f.provider.RegisterClient(ctx, admin, RegisterOAuthClient{TenantID: "a", ClientID: "web", Public: true,
		OAuthClientSettings: OAuthClientSettings{Name: "Web", RedirectURIs: []string{f.origin + "/callback"}}}); err != nil {
		t.Fatal(err)
	}
	query := form("client_id", "web", "response_type", "code", "redirect_uri", f.origin+"/callback", "scope", "openid")
	missing := fetch(t, "GET", str(discovery, "authorization_endpoint")+"?"+query, nil, "")
	if missing.Status != 303 || !strings.Contains(missing.Header.Get("location"), "error=invalid_request") {
		t.Fatalf("expected a PKCE refusal, got %d %s", missing.Status, missing.Header.Get("location"))
	}
}

func basicAuth(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))
}

func TestMachineTokensIntrospectionAndRevocation(t *testing.T) {
	f := newOAuthFixture(t, nil)
	ctx := context.Background()
	client, err := f.provider.RegisterClient(ctx, admin, RegisterOAuthClient{TenantID: "a", ClientID: "machine", ServiceAccountID: "service-a",
		OAuthClientSettings: OAuthClientSettings{Name: "Machine", RedirectURIs: []string{}, GrantTypes: []string{"client_credentials"}, Scopes: []string{"profile"}}})
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"authorization": basicAuth("machine", client.ClientSecret), "content-type": formType}
	tokenResponse := fetch(t, "POST", f.origin+"/oidc/token", headers, "grant_type=client_credentials&scope=profile")
	if tokenResponse.Status != 200 {
		t.Fatalf("token status %d %s", tokenResponse.Status, tokenResponse.Body)
	}
	token := tokenResponse.JSON(t)
	accessToken := str(token, "access_token")
	introspection := fetch(t, "POST", f.origin+"/oidc/token/introspection", headers, form("token", accessToken))
	details := introspection.JSON(t)
	if introspection.Status != 200 || details.Get("active") != true || str(details, "tenant_id") != "a" || str(details, "identity_id") != "service-a" {
		t.Fatalf("unexpected introspection %d %s", introspection.Status, introspection.Body)
	}
	artifacts, _ := f.store.Find(ctx, "oauthArtifacts", nil, nil)
	if strings.Contains(stringify(anyObjects(artifacts)), accessToken) {
		t.Fatal("the access token is stored in clear")
	}
	clients, _ := f.store.Find(ctx, "oauthClients", nil, nil)
	if strings.Contains(stringify(anyObjects(clients)), client.ClientSecret) {
		t.Fatal("the client secret is stored in clear")
	}
	update(t, f.store, "identities", "service-a", func(record *core.Object) { record.Set("status", "disabled") })
	disabled := fetch(t, "POST", f.origin+"/oidc/token/introspection", headers, form("token", accessToken))
	if disabled.Status != 401 {
		t.Fatalf("expected 401 for a disabled service account, got %d", disabled.Status)
	}
	update(t, f.store, "identities", "service-a", func(record *core.Object) { record.Set("status", "active") })
	if err := f.provider.RevokeClient(ctx, admin, "a", "machine"); err != nil {
		t.Fatal(err)
	}
	revoked := fetch(t, "POST", f.origin+"/oidc/token", headers, "grant_type=client_credentials")
	if revoked.Status != 401 {
		t.Fatalf("expected 401 after revocation, got %d", revoked.Status)
	}
}

func anyObjects(rows []*core.Object) []any {
	out := make([]any, len(rows))
	for index, row := range rows {
		out[index] = row
	}
	return out
}

func TestRegistrationIsAuthenticatedAndTenantBindingImmutable(t *testing.T) {
	f := newOAuthFixture(t, nil)
	ctx := context.Background()
	machine := RegisterOAuthClient{TenantID: "a", ClientID: "machine", ServiceAccountID: "service-a",
		OAuthClientSettings: OAuthClientSettings{Name: "Machine", RedirectURIs: []string{}, GrantTypes: []string{"client_credentials"}}}
	_, err := f.provider.RegisterClient(ctx, core.CredentialInput{Token: "forged"}, machine)
	expectIamError(t, err, 403, "")
	if _, err := f.provider.RegisterClient(ctx, admin, machine); err != nil {
		t.Fatal(err)
	}
	other := machine
	other.TenantID, other.ServiceAccountID = "b", "service-b"
	_, err = f.provider.RegisterClient(ctx, admin, other)
	expectIamError(t, err, 409, "")
	bad := RegisterOAuthClient{TenantID: "a", ClientID: "bad-public", Public: true, ServiceAccountID: "service-a",
		OAuthClientSettings: OAuthClientSettings{Name: "Bad", RedirectURIs: []string{}, GrantTypes: []string{"client_credentials"}}}
	_, err = f.provider.RegisterClient(ctx, admin, bad)
	expectIamError(t, err, 0, "INVALID_INPUT")
}

func TestPKCEAndRefreshFamilies(t *testing.T) {
	for _, concurrent := range []bool{false, true} {
		t.Run(map[bool]string{false: "sequential", true: "concurrent"}[concurrent], func(t *testing.T) {
			f := newOAuthFixture(t, nil)
			ctx := context.Background()
			if _, err := f.provider.RegisterClient(ctx, admin, RegisterOAuthClient{TenantID: "a", ClientID: "public-web", Public: true,
				OAuthClientSettings: OAuthClientSettings{Name: "Web", RedirectURIs: []string{f.origin + "/callback"}, Scopes: []string{"openid", "profile", "offline_access", "iam"}}}); err != nil {
				t.Fatal(err)
			}
			verifier, challenge := pkcePair()
			b := newBrowser(t)
			params := form("client_id", "public-web", "response_type", "code", "redirect_uri", f.origin+"/callback",
				"scope", "openid profile offline_access iam", "prompt", "consent", "state", "state",
				"code_challenge", challenge, "code_challenge_method", "S256")
			result := b.visit("GET", f.origin+"/oidc/auth?"+params, nil, "")
			redirect := result.Header.Get("location")
			if !strings.Contains(redirect, "/interactions/") {
				t.Fatalf("expected an interaction, got %d %q %s", result.Status, redirect, result.Body)
			}
			details := b.visit("GET", resolve(f.origin, redirect), nil, "")
			if str(details.JSON(t), "tenantId") != "a" {
				t.Fatalf("unexpected details %s", details.Body)
			}
			if csrf := b.visit("POST", resolve(f.origin, redirect), nil, ""); csrf.Status != 403 {
				t.Fatalf("expected a CSRF refusal, got %d", csrf.Status)
			}
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
			exchange := func(body string) *httpResult {
				return fetch(t, "POST", f.origin+"/oidc/token", map[string]string{"content-type": formType}, body)
			}
			tokenResponse := exchange(form("grant_type", "authorization_code", "client_id", "public-web", "code", code,
				"code_verifier", verifier, "redirect_uri", f.origin+"/callback"))
			if tokenResponse.Status != 200 {
				t.Fatalf("token status %d %s", tokenResponse.Status, tokenResponse.Body)
			}
			tokens := tokenResponse.JSON(t)
			if str(tokens, "refresh_token") == "" {
				t.Fatalf("no refresh token: %s", tokenResponse.Body)
			}
			idToken := decodePayload(t, str(tokens, "id_token"))
			if str(idToken, "sub") != "user-a" || str(idToken, "tenant_id") != "a" {
				t.Fatalf("unexpected ID token %s", stringify(idToken))
			}
			userinfo := fetch(t, "GET", f.origin+"/oidc/me", map[string]string{"authorization": "Bearer " + str(tokens, "access_token")}, "")
			if userinfo.Status != 200 {
				t.Fatalf("userinfo status %d %s", userinfo.Status, userinfo.Body)
			}
			claims := userinfo.JSON(t)
			if str(claims, "sub") != "user-a" || stringify(claims.Get("roles")) != `["role-direct","role-group"]` ||
				stringify(claims.Get("groups")) != `["group-a"]` || stringify(claims.Get("attributes")) != `{"department":"finance"}` {
				t.Fatalf("unexpected userinfo %s", userinfo.Body)
			}
			rotate := exchange(form("grant_type", "refresh_token", "client_id", "public-web", "refresh_token", str(tokens, "refresh_token")))
			if rotate.Status != 200 {
				t.Fatalf("rotation status %d %s", rotate.Status, rotate.Body)
			}
			rotated := rotate.JSON(t)
			if str(rotated, "refresh_token") == str(tokens, "refresh_token") {
				t.Fatal("the refresh token did not rotate")
			}
			if concurrent {
				var wg sync.WaitGroup
				raced := make([]*httpResult, 2)
				for index := range raced {
					wg.Add(1)
					go func(index int) {
						defer wg.Done()
						raced[index] = exchange(form("grant_type", "refresh_token", "client_id", "public-web", "refresh_token", str(rotated, "refresh_token")))
					}(index)
				}
				wg.Wait()
				ok, bad := 0, 0
				for _, response := range raced {
					switch response.Status {
					case 200:
						ok++
					case 400:
						bad++
					}
				}
				if ok > 1 || bad == 0 {
					t.Fatalf("raced refreshes: %d ok, %d refused", ok, bad)
				}
				for _, response := range raced {
					if response.Status == 200 {
						revoked := exchange(form("grant_type", "refresh_token", "client_id", "public-web", "refresh_token", str(response.JSON(t), "refresh_token")))
						if revoked.Status != 400 {
							t.Fatalf("expected the family revoked, got %d", revoked.Status)
						}
					}
				}
			}
			replay := exchange(form("grant_type", "refresh_token", "client_id", "public-web", "refresh_token", str(tokens, "refresh_token")))
			if replay.Status != 400 || str(replay.JSON(t), "error") != "invalid_grant" {
				t.Fatalf("expected invalid_grant on replay, got %d %s", replay.Status, replay.Body)
			}
			family := exchange(form("grant_type", "refresh_token", "client_id", "public-web", "refresh_token", str(rotated, "refresh_token")))
			if family.Status != 400 || str(family.JSON(t), "error") != "invalid_grant" {
				t.Fatalf("expected the family revoked, got %d %s", family.Status, family.Body)
			}
		})
	}
}

func TestAdapterPersistsScopesAndConsumesAtomically(t *testing.T) {
	f := newOAuthFixture(t, nil)
	ctx := context.Background()
	if _, err := f.provider.RegisterClient(ctx, admin, RegisterOAuthClient{TenantID: "a", ClientID: "web",
		OAuthClientSettings: OAuthClientSettings{Name: "Web", RedirectURIs: []string{"https://app.test/callback"}}}); err != nil {
		t.Fatal(err)
	}
	adapter, err := CreateProviderAdapter(f.store, f.key, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, second := adapter.Model("RefreshToken"), adapter.Model("RefreshToken")
	insert(t, f.store, "oauthGrantSessions", core.NewObject("id", hash("grant"), "tenantId", "a", "sessionId", "session-a", "identityId", "user-a"))
	if err := first.Upsert(ctx, "refresh-secret", core.NewObject("clientId", "web", "accountId", "user-a", "grantId", "grant", "jti", "refresh-secret"), 60); err != nil {
		t.Fatal(err)
	}
	found, err := second.Find(ctx, "refresh-secret")
	if err != nil || found == nil || str(found, "accountId") != "user-a" {
		t.Fatalf("expected the artifact from another adapter, got %v %v", found, err)
	}
	err = first.Upsert(ctx, "foreign", core.NewObject("clientId", "web", "accountId", "user-b"), 60)
	if e, ok := asOIDC(err); !ok || e.Code != "invalid_grant" {
		t.Fatalf("expected invalid_grant, got %v", err)
	}
	var wg sync.WaitGroup
	results := make([]error, 2)
	for index, model := range []*ModelAdapter{first, second} {
		wg.Add(1)
		go func(index int, model *ModelAdapter) {
			defer wg.Done()
			results[index] = model.Consume(ctx, "refresh-secret")
		}(index, model)
	}
	wg.Wait()
	succeeded := 0
	for _, err := range results {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("expected one consumption, got %d (%v)", succeeded, results)
	}
	if found, _ := first.Find(ctx, "refresh-secret"); found != nil {
		t.Fatal("expected the family revoked by the second consumption")
	}
	if err := second.RevokeByGrantID(ctx, "grant"); err != nil {
		t.Fatal(err)
	}
	if found, _ := first.Find(ctx, "refresh-secret"); found != nil {
		t.Fatal("expected no artifact after revocation")
	}
	insert(t, f.store, "oauthGrantSessions", core.NewObject("id", hash("session-grant"), "tenantId", "a", "sessionId", "session-a", "identityId", "user-a"))
	session := adapter.Model("Session")
	if err := session.Upsert(ctx, "anonymous", core.NewObject("uid", "uid"), 60); err != nil {
		t.Fatal(err)
	}
	if err := session.Upsert(ctx, "anonymous", core.NewObject("uid", "uid", "accountId", "user-a",
		"authorizations", core.NewObject("web", core.NewObject("grantId", "session-grant"))), 60); err != nil {
		t.Fatal(err)
	}
	if found, _ := session.FindByUID(ctx, "uid"); found == nil || str(found, "accountId") != "user-a" {
		t.Fatalf("expected the session by uid, got %v", found)
	}
	err = session.Upsert(ctx, "anonymous", core.NewObject("uid", "uid", "accountId", "user-b"), 60)
	if e, ok := asOIDC(err); !ok || e.Code != "invalid_grant" {
		t.Fatalf("expected invalid_grant for a rebinding, got %v", err)
	}
	insert(t, f.store, "oauthGrantSessions", core.NewObject("id", hash("live-grant"), "tenantId", "a", "sessionId", "session-a", "identityId", "user-a"))
	if err := first.Upsert(ctx, "another-refresh", core.NewObject("clientId", "web", "accountId", "user-a", "grantId", "live-grant"), 60); err != nil {
		t.Fatal(err)
	}
	remove(t, f.store, "sessions", "session-a")
	if found, _ := first.Find(ctx, "another-refresh"); found != nil {
		t.Fatal("expected the artifact to die with its IAM session")
	}
}

func TestOIDCLoginVerifiesSignaturesNonceAndPKCE(t *testing.T) {
	store := newTestStore(t)
	seedOAuthTenants(t, store)
	signing, public := testRSAKey()
	var mu sync.Mutex
	nonce, challenge, badNonce, exchanges := "", "", false, 0
	origin := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_, _ = w.Write([]byte(stringify(core.NewObject("issuer", origin, "authorization_endpoint", origin+"/authorize",
				"token_endpoint", origin+"/token", "jwks_uri", origin+"/jwks", "response_types_supported", []any{"code"},
				"subject_types_supported", []any{"public"}, "id_token_signing_alg_values_supported", []any{"RS256"}))))
		case "/jwks":
			_, _ = w.Write([]byte(stringify(core.NewObject("keys", []any{public}))))
		case "/token":
			_ = r.ParseForm()
			mu.Lock()
			defer mu.Unlock()
			if sha256B64URL(r.PostForm.Get("code_verifier")) != challenge {
				t.Errorf("PKCE verifier mismatch")
			}
			exchanges++
			tokenNonce := nonce
			if badNonce {
				tokenNonce = "wrong"
			}
			now := epoch(wallNow())
			jwt := signJWT(t, signing, "RS256", core.NewObject("kid", "test-key"), core.NewObject("nonce", tokenNonce,
				"email", "same@example.test", "email_verified", true, "name", "Federated", "iss", origin, "aud", "login",
				"sub", "stable-subject", "iat", now, "exp", now+300))
			_, _ = w.Write([]byte(stringify(core.NewObject("access_token", "provider-access-token", "token_type", "Bearer", "id_token", jwt, "expires_in", 300))))
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte("{}"))
		}
	}))
	defer server.Close()
	origin = server.URL
	var identities []*core.Object
	var identitiesMu sync.Mutex
	login, err := CreateOAuthLogin(OAuthLoginConfig{Store: store, AllowInsecureLocalhost: true,
		Connections: []OAuthLoginConnection{{ID: "login-a", TenantID: "a", Kind: "oidc", Issuer: origin, ClientID: "login",
			RedirectURI: origin + "/callback", TrustScimProvisioned: []string{"scim-1"},
			MapAttributes: func(claims *core.Object) (*core.Object, error) {
				return core.NewObject("upstreamSubject", claims.Get("sub")), nil
			}}},
		CompleteAuthentication: func(_ context.Context, identity FederatedIdentity) (any, error) {
			identitiesMu.Lock()
			defer identitiesMu.Unlock()
			identities = append(identities, identity)
			return core.NewObject("verified", true), nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	begin, err := login.Begin(ctx, "login-a", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	authURL, _ := url.Parse(begin.URL)
	mu.Lock()
	nonce, challenge = authURL.Query().Get("nonce"), authURL.Query().Get("code_challenge")
	mu.Unlock()
	returned := origin + "/callback?code=valid&state=" + url.QueryEscape(begin.State)
	_, err = login.Callback(ctx, "login-a", returned, "forged")
	expectIamError(t, err, 0, "OAUTH_STATE")
	var wg sync.WaitGroup
	results := make([]error, 2)
	for index := range results {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			_, results[index] = login.Callback(ctx, "login-a", returned, begin.Binding)
		}(index)
	}
	wg.Wait()
	succeeded := 0
	for _, err := range results {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 || exchanges != 1 {
		t.Fatalf("expected one callback and one exchange, got %d and %d (%v)", succeeded, exchanges, results)
	}
	expected := `[{"tenantId":"a","providerId":"login-a","issuer":"` + origin + `","subject":"stable-subject","email":"same@example.test","emailVerified":true,"name":"Federated","attributes":{"upstreamSubject":"stable-subject"},"trustScimProvisioned":["scim-1"]}]`
	if got := stringify(anyObjects(identities)); got != expected {
		t.Fatalf("unexpected identities\n%s\n%s", got, expected)
	}
	_, err = CreateOAuthLogin(OAuthLoginConfig{Store: store, AllowInsecureLocalhost: true,
		Connections: []OAuthLoginConnection{{ID: "bad-trust", TenantID: "a", Kind: "oidc", Issuer: origin, ClientID: "login",
			RedirectURI: origin + "/other-callback", TrustScimProvisioned: "yes"}},
		CompleteAuthentication: func(context.Context, FederatedIdentity) (any, error) { return nil, nil }})
	if err == nil || !strings.Contains(err.Error(), "trustScimProvisioned") {
		t.Fatalf("expected a trustScimProvisioned refusal, got %v", err)
	}
	again, err := login.Begin(ctx, "login-a", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	againURL, _ := url.Parse(again.URL)
	mu.Lock()
	nonce, challenge, badNonce = againURL.Query().Get("nonce"), againURL.Query().Get("code_challenge"), true
	mu.Unlock()
	if _, err := login.Callback(ctx, "login-a", origin+"/callback?code=valid&state="+url.QueryEscape(again.State), again.Binding); err == nil {
		t.Fatal("expected a nonce mismatch to fail")
	}
	if len(identities) != 1 {
		t.Fatalf("expected one identity, got %d", len(identities))
	}
}

func TestOAuth2MappingAndBrowserBoundLinking(t *testing.T) {
	store := newTestStore(t)
	seedOAuthTenants(t, store)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch {
		case r.URL.Path == "/token":
			_, _ = w.Write([]byte(`{"access_token":"verified-token","token_type":"Bearer"}`))
		case r.URL.Path == "/profile" && r.Header.Get("authorization") == "Bearer verified-token":
			_, _ = w.Write([]byte(`{"id":"provider-subject","mail":"same@example.test"}`))
		default:
			w.WriteHeader(401)
			_, _ = w.Write([]byte("{}"))
		}
	}))
	defer server.Close()
	origin := server.URL
	identity, _ := store.Get(context.Background(), "identities", "user-a")
	now := wallNow()
	principal := &auth.Principal{Identity: identity, Session: core.NewObject("id", "link-session", "tenantId", "a", "identityId", "user-a",
		"tokenHash", "unused", "createdAt", now, "authenticatedAt", now, "lastSeenAt", now, "expiresAt", now+600000, "mfa", false, "kind", "user")}
	var completed []*core.Object
	login, err := CreateOAuthLogin(OAuthLoginConfig{Store: store, AllowInsecureLocalhost: true, TrustedOrigins: []string{origin},
		Connections: []OAuthLoginConnection{{ID: "custom", Kind: "oauth2", TenantID: "a", ClientID: "custom", Issuer: origin,
			RedirectURI: origin + "/callback", AuthorizationEndpoint: origin + "/authorize", TokenEndpoint: origin + "/token",
			UserInfoEndpoint: origin + "/profile",
			MapProfile: func(profile *core.Object) (*MappedProfile, error) {
				email := jsString(profile.Get("mail"))
				verified := true
				return &MappedProfile{Subject: jsString(profile.Get("id")), Email: &email, EmailVerified: &verified}, nil
			}}},
		Authenticate: func(_ context.Context, credential core.CredentialInput) (*auth.Principal, error) {
			if credential.Headers.Get("authorization") != "Bearer local-session" {
				return nil, core.NewIamError("FORBIDDEN", "Forbidden", 403)
			}
			return principal, nil
		},
		CompleteAuthentication: func(_ context.Context, identity FederatedIdentity) (any, error) {
			completed = append(completed, identity)
			return core.NewObject("linked", true), nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	request := func(headers map[string]string) *Response {
		r := httptest.NewRequest("POST", origin+"/oauth/login/custom", nil)
		for key, value := range headers {
			r.Header.Set(key, value)
		}
		return login.Handler(ctx, r)
	}
	forged := request(map[string]string{"authorization": "Bearer local-session", "content-type": "application/json", "x-better-iam": "1"})
	if forged == nil || forged.Status != 403 {
		t.Fatalf("expected a CSRF refusal, got %v", forged)
	}
	response := request(map[string]string{"origin": origin, "authorization": "Bearer local-session", "content-type": "application/json", "x-better-iam": "1"})
	if response == nil || response.Status != 200 {
		t.Fatalf("expected the begin URL, got %v", response)
	}
	begin := mustParse(t, string(response.Body))
	target, _ := url.Parse(str(begin, "url"))
	cookie := response.Header.Get("set-cookie")
	if strings.Contains(cookie, "__Host-") || strings.Contains(cookie, "Secure") {
		t.Fatalf("unexpected secure cookie on http: %s", cookie)
	}
	binding := strings.SplitN(strings.SplitN(cookie, ";", 2)[0], "=", 2)[1]
	result, err := login.Callback(ctx, "custom", origin+"/callback?code=verified&state="+target.Query().Get("state"), binding)
	if err != nil || stringify(result) != `{"linked":true}` {
		t.Fatalf("unexpected callback %v %v", result, err)
	}
	expected := `[{"tenantId":"a","providerId":"custom","issuer":"` + origin + `","subject":"provider-subject","email":"same@example.test","emailVerified":true,"linkingIdentityId":"user-a","linkingSessionId":"link-session"}]`
	if got := stringify(anyObjects(completed)); got != expected {
		t.Fatalf("unexpected identities\n%s\n%s", got, expected)
	}
	principal.Identity = principal.Identity.Clone()
	principal.Identity.Set("rootAdmin", true)
	header := http.Header{}
	header.Set("authorization", "Bearer local-session")
	_, err = login.Begin(ctx, "custom", &core.CredentialInput{Headers: header}, nil)
	expectIamError(t, err, 403, "")
	_ = time.Second
}
