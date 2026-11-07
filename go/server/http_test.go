package server

// Ports of tests/http-hygiene.test.ts, tests/cookie-options.test.ts and the transport parts of
// tests/http-hardening.test.ts and tests/security-e15e8e-http.test.ts: response hardening, request IDs, cookies,
// CSRF, CORS, body limits, the operational routes and the router's 404s.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

type iamFixture struct {
	t     *testing.T
	iam   *BetterIam
	root  *core.Object
	spans []IamSpan
	mu    sync.Mutex
}

// newIam composes a server on an in-memory database, initializes it and bootstraps the root.
func newIam(t *testing.T, baseURL string, mutate func(options *BetterIamOptions)) *iamFixture {
	t.Helper()
	fixture := &iamFixture{t: t}
	options := &BetterIamOptions{
		Database: newStore(t), Secret: "http-hygiene-test-secret-with-at-least-32-chars", BaseURL: baseURL,
		Observability: &ObservabilityOptions{OnSpan: func(span IamSpan) {
			fixture.mu.Lock()
			defer fixture.mu.Unlock()
			fixture.spans = append(fixture.spans, span)
		}},
	}
	if mutate != nil {
		mutate(options)
	}
	iam, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(iam.Close)
	ctx := context.Background()
	if err := iam.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	root, err := iam.Bootstrap(ctx, core.NewObject("email", "root@example.test", "name", "Root", "password", "a strong root test password"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.iam, fixture.root = iam, root
	return fixture
}

func (f *iamFixture) rootTenantID() string {
	return jsString(member(f.root.Get("tenant"), "id"))
}

func (f *iamFixture) createIdentity(email, name, password string) *core.Object {
	f.t.Helper()
	identity, err := core.Transact(context.Background(), f.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return f.iam.Auth.CreateIdentity(ctx, tx, auth.CreateIdentityInput{
			TenantID: f.rootTenantID(), Email: email, Name: name, Password: password, HasPassword: true, EmailVerified: true,
		})
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return identity
}

// fetch is the fetch-style transport (TypeScript iam.handler).
func (f *iamFixture) fetch(method, url string, headers map[string]string, body string) *Response {
	f.t.Helper()
	var reader io.Reader
	if body != "" || method == http.MethodPost {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, url, reader)
	if reader == nil {
		request.Body = http.NoBody
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	return f.iam.Handle(request)
}

func (f *iamFixture) post(base, path string, body string, headers map[string]string) *Response {
	merged := map[string]string{"content-type": "application/json", "x-better-iam": "1"}
	for key, value := range headers {
		merged[key] = value
	}
	return f.fetch(http.MethodPost, base+"/api/iam/"+path, merged, body)
}

func jsonBody(t *testing.T, response *Response) *core.Object {
	t.Helper()
	parsed, err := core.ParseJSON(response.Body)
	if err != nil {
		t.Fatalf("invalid JSON %q: %v", response.Body, err)
	}
	object, _ := parsed.(*core.Object)
	return object
}

func errorCode(t *testing.T, response *Response) string {
	return jsString(member(jsonBody(t, response).Get("error"), "code"))
}

func TestHTTPHygieneHardensResponsesAndEchoesRequestIDs(t *testing.T) {
	const base = "http://localhost:3000"
	f := newIam(t, base, nil)
	f.createIdentity("alice@example.test", "Alice", "a strong alice password")
	signIn := `{"tenantId":"` + f.rootTenantID() + `","email":"alice@example.test","password":"a strong alice password"}`
	ok := f.post(base, "auth/signIn", signIn, map[string]string{"x-request-id": "req-123.abc"})
	if ok.Status != 200 {
		t.Fatalf("signIn: %d %s", ok.Status, ok.Body)
	}
	for header, want := range map[string]string{
		"X-Request-Id": "req-123.abc", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
	} {
		if got := ok.Header.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	var httpSpan *IamSpan
	for index := range f.spans {
		if f.spans[index].Kind == "http" {
			httpSpan = &f.spans[index]
			break
		}
	}
	if httpSpan == nil || httpSpan.Name != "auth/signIn" || httpSpan.RequestID != "req-123.abc" || httpSpan.Outcome != "ok" {
		t.Errorf("http span = %+v", httpSpan)
	}
	denied := f.post(base, "authorize", `{"tenantId":"`+f.rootTenantID()+`","action":"iam:groups:create","resource":{"type":"iam","id":"x"}}`, map[string]string{"x-request-id": "req-456"})
	if denied.Status != 401 || denied.Header.Get("X-Request-Id") != "req-456" || denied.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("unauthenticated authorize: %d %v", denied.Status, denied.Header)
	}
	// Hostile or oversized IDs are dropped rather than echoed.
	if junk := f.post(base, "auth/signIn", `{}`, map[string]string{"x-request-id": "bad id <script>"}); junk.Header.Get("X-Request-Id") != "" {
		t.Error("a hostile request ID was echoed")
	}
	if long := f.post(base, "auth/signIn", `{}`, map[string]string{"x-request-id": strings.Repeat("a", 200)}); long.Header.Get("X-Request-Id") != "" {
		t.Error("an oversized request ID was echoed")
	}
	// Operational endpoints carry the same hardening.
	health := f.fetch(http.MethodGet, base+"/api/iam/health", nil, "")
	if health.Status != 200 || health.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("health: %d %v", health.Status, health.Header)
	}
	if status := jsonBody(t, health).Get("status"); status != "ok" {
		t.Errorf("health status %v", status)
	}
	// Session lists mark the caller's own session; the MFA status summarizes what is set up.
	token := jsString(member(jsonBody(t, ok).Get("data"), "token"))
	if _, err := f.iam.API.Auth.SignIn(context.Background(), Input[apitypes.AuthSignInInput](core.NewObject("tenantId", f.rootTenantID(), "email", "alice@example.test", "password", "a strong alice password"))); err != nil {
		t.Fatal(err)
	}
	sessions, err := f.iam.API.Auth.ListSessions(context.Background(), core.CredentialInput{Token: token}, Input[*core.Object](core.NewObject()))
	if err != nil {
		t.Fatal(err)
	}
	list, _ := sessions.Value.([]*core.Object)
	current := 0
	for _, session := range list {
		if session.Get("current") == true {
			current++
		}
	}
	if len(list) != 2 || current != 1 {
		t.Errorf("sessions %d, current %d", len(list), current)
	}
	status, err := f.iam.API.Auth.MfaStatus(context.Background(), core.CredentialInput{Token: token}, Input[*core.Object](core.NewObject()))
	if err != nil {
		t.Fatal(err)
	}
	if text, _, _ := core.Stringify(status.Value); text != `{"enabled":false,"recoveryCodesRemaining":0,"passkeys":0,"trustedDevices":0,"sessionMfa":false}` {
		t.Errorf("mfaStatus = %s", text)
	}
}

const cookieOrigin = "https://iam.example.com"

func cookieFixture(t *testing.T, mutate func(options *BetterIamOptions)) (*iamFixture, func(headers map[string]string) *Response) {
	f := newIam(t, cookieOrigin, mutate)
	f.createIdentity("owner@example.test", "Owner", "a strong tenant owner password")
	signIn := func(headers map[string]string) *Response {
		return f.post(cookieOrigin, "auth/signIn", `{"tenantId":"`+f.rootTenantID()+`","email":"owner@example.test","password":"a strong tenant owner password"}`, headers)
	}
	return f, signIn
}

func sessionCookie(response *Response) string {
	for _, line := range response.Header.Values("Set-Cookie") {
		if strings.HasPrefix(line, "__Host-better-iam.session=") {
			return line
		}
	}
	return ""
}

var maxAgePattern = regexp.MustCompile(`; Max-Age=\d+`)

func TestCookieOptionsPersistentByDefaultAndBrowserSessionOnRequest(t *testing.T) {
	f, signIn := cookieFixture(t, nil)
	persistent := sessionCookie(signIn(nil))
	if !maxAgePattern.MatchString(persistent) || !strings.Contains(persistent, "HttpOnly; Secure; SameSite=Lax; Path=/") {
		t.Errorf("persistent cookie %q", persistent)
	}
	transient := sessionCookie(signIn(map[string]string{"x-better-iam-persistent": "0"}))
	if strings.Contains(transient, "Max-Age") || !strings.Contains(transient, "HttpOnly; Secure; SameSite=Lax; Path=/") {
		t.Errorf("transient cookie %q", transient)
	}
	// An unknown header value falls back to the default.
	if !maxAgePattern.MatchString(sessionCookie(signIn(map[string]string{"x-better-iam-persistent": "maybe"}))) {
		t.Error("an unknown persistence value did not fall back to the default")
	}
	// Preflight requests advertise the header, and the request identifier, to cross-origin callers.
	preflight := f.fetch(http.MethodOptions, cookieOrigin+"/api/iam/auth/signIn", map[string]string{"origin": cookieOrigin}, "")
	allowed := preflight.Header.Get("Access-Control-Allow-Headers")
	if preflight.Status != 204 || !strings.Contains(allowed, "x-better-iam-persistent") || !strings.Contains(allowed, "x-request-id") {
		t.Errorf("preflight %d %q", preflight.Status, allowed)
	}
}

func TestCookieOptionsDeploymentDefaultsAndStrictSameSite(t *testing.T) {
	strict, persistent := "strict", false
	f, signIn := cookieFixture(t, func(options *BetterIamOptions) {
		options.HTTP = &HttpOptions{PersistentCookies: &persistent, CookieSameSite: &strict}
	})
	transient := sessionCookie(signIn(nil))
	if strings.Contains(transient, "Max-Age") || !strings.Contains(transient, "SameSite=Strict") {
		t.Errorf("transient cookie %q", transient)
	}
	asked := sessionCookie(signIn(map[string]string{"x-better-iam-persistent": "1"}))
	if !maxAgePattern.MatchString(asked) || !strings.Contains(asked, "SameSite=Strict") {
		t.Errorf("persistent cookie %q", asked)
	}
	// Signing out clears the cookie with the same attributes.
	token := strings.SplitN(strings.SplitN(sessionCookie(signIn(nil)), ";", 2)[0], "=", 2)[1]
	signOut := f.post(cookieOrigin, "auth/signOut", `{}`, map[string]string{"origin": cookieOrigin, "cookie": "__Host-better-iam.session=" + token})
	if signOut.Status != 200 || !strings.Contains(sessionCookie(signOut), "SameSite=Strict; Path=/; Max-Age=0") {
		t.Errorf("signOut %d %q %s", signOut.Status, sessionCookie(signOut), signOut.Body)
	}
	// The options are validated at construction.
	none := "none"
	_, err := New(&BetterIamOptions{Database: newStore(t), Secret: "cookie-options-test-secret-with-32-chars!!", BaseURL: cookieOrigin, HTTP: &HttpOptions{CookieSameSite: &none}})
	if err == nil || !strings.Contains(err.Error(), "cookieSameSite") {
		t.Errorf("cookieSameSite none: %v", err)
	}
}

func TestHTTPCSRFBoundaryCORSAndBodyLimits(t *testing.T) {
	const base = "http://localhost:3000"
	f := newIam(t, base, nil)
	// JSON and the X-Better-IAM header are both required.
	noMarker := f.fetch(http.MethodPost, base+"/api/iam/auth/signIn", map[string]string{"content-type": "application/json"}, `{}`)
	if noMarker.Status != 403 || errorCode(t, noMarker) != "CSRF_REJECTED" {
		t.Errorf("no X-Better-IAM: %d %s", noMarker.Status, noMarker.Body)
	}
	form := f.fetch(http.MethodPost, base+"/api/iam/auth/signIn", map[string]string{"content-type": "text/plain", "x-better-iam": "1"}, `{}`)
	if form.Status != 403 || errorCode(t, form) != "CSRF_REJECTED" {
		t.Errorf("text/plain: %d %s", form.Status, form.Body)
	}
	// Content types are matched case-insensitively and with parameters.
	upper := f.post(base, "auth/getSession", `{}`, map[string]string{"content-type": "Application/JSON; charset=utf-8"})
	if upper.Status != 401 {
		t.Errorf("Application/JSON: %d %s", upper.Status, upper.Body)
	}
	// A cookie request must carry an Origin.
	cookie := f.post(base, "auth/getSession", `{}`, map[string]string{"cookie": "better-iam.session=x"})
	if cookie.Status != 403 || jsString(member(jsonBody(t, cookie).Get("error"), "message")) != "Cookie requests require Origin" {
		t.Errorf("cookie without origin: %d %s", cookie.Status, cookie.Body)
	}
	// An untrusted Origin is refused without CORS headers; a trusted one gets them, on errors too.
	untrusted := f.post(base, "auth/getSession", `{}`, map[string]string{"origin": "https://evil.example"})
	if untrusted.Status != 403 || errorCode(t, untrusted) != "UNTRUSTED_ORIGIN" || untrusted.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("untrusted origin: %d %v", untrusted.Status, untrusted.Header)
	}
	trusted := f.post(base, "auth/getSession", `{}`, map[string]string{"origin": base})
	if trusted.Status != 401 || trusted.Header.Get("Access-Control-Allow-Origin") != base || trusted.Header.Get("Access-Control-Allow-Credentials") != "true" ||
		trusted.Header.Get("Vary") != "Origin" || trusted.Header.Get("Access-Control-Expose-Headers") != "retry-after, x-request-id" {
		t.Errorf("trusted origin: %d %v", trusted.Status, trusted.Header)
	}
	// Bodies: invalid JSON, non-objects, oversized bodies.
	for _, body := range []string{`{`, `[]`, `"x"`, `null`, ``} {
		response := f.post(base, "auth/signIn", body, nil)
		if response.Status != 400 || errorCode(t, response) != "INVALID_INPUT" || jsString(member(jsonBody(t, response).Get("error"), "message")) != "Invalid JSON" {
			t.Errorf("body %q: %d %s", body, response.Status, response.Body)
		}
	}
	large := f.post(base, "auth/signIn", `{"x":"`+strings.Repeat("a", 70000)+`"}`, nil)
	if large.Status != 413 || errorCode(t, large) != "PAYLOAD_TOO_LARGE" {
		t.Errorf("large body: %d %s", large.Status, large.Body)
	}
	// Methods: GET is operational, others are refused.
	put := f.fetch(http.MethodPut, base+"/api/iam/auth/signIn", nil, "")
	if put.Status != 405 || errorCode(t, put) != "METHOD_NOT_ALLOWED" {
		t.Errorf("PUT: %d %s", put.Status, put.Body)
	}
	missing := f.fetch(http.MethodGet, base+"/api/iam/nothing", nil, "")
	if missing.Status != 404 || errorCode(t, missing) != "NOT_FOUND" {
		t.Errorf("GET unknown: %d %s", missing.Status, missing.Body)
	}
	jwks := f.fetch(http.MethodGet, base+"/api/iam/.well-known/jwks.json", nil, "")
	if jwks.Status != 404 {
		t.Errorf("jwks without sts.jwt: %d", jwks.Status)
	}
	outside := f.fetch(http.MethodGet, base+"/elsewhere", nil, "")
	if outside.Status != 404 || string(outside.Body) != `{"error":{"code":"NOT_FOUND","message":"Not found"}}` {
		t.Errorf("outside the base path: %d %s", outside.Status, outside.Body)
	}
	// Routes: unknown groups, methods, extra segments and helpers that are not routed.
	for _, path := range []string{"nothing/here", "tenants/nothing", "tenants/create/extra", "auth/createIdentity", "auth", "plugins/none/x"} {
		response := f.post(base, path, `{"tenantId":"t"}`, nil)
		if response.Status != 404 || jsString(member(jsonBody(t, response).Get("error"), "message")) != "Endpoint not found" {
			t.Errorf("%s: %d %s", path, response.Status, response.Body)
		}
	}
}

func TestNodeTransportLimitsAndMethods(t *testing.T) {
	const base = "http://localhost:3000"
	f := newIam(t, base, nil)
	serve := func(method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		recorder := httptest.NewRecorder()
		f.iam.ServeHTTP(recorder, request)
		return recorder
	}
	if trace := serve("TRACE", "/api/iam/health", "", nil); trace.Code != 405 || !strings.Contains(trace.Body.String(), "Method is not supported") {
		t.Errorf("TRACE: %d %s", trace.Code, trace.Body)
	}
	if large := serve(http.MethodPost, "/api/iam/auth/signIn", strings.Repeat("a", 65537), map[string]string{"content-type": "application/json", "x-better-iam": "1"}); large.Code != 413 || large.Body.String() != "Request too large" {
		t.Errorf("node body limit: %d %s", large.Code, large.Body)
	}
	// An empty POST body is not `{}` on the Node transport: it is invalid JSON.
	if empty := serve(http.MethodPost, "/api/iam/auth/signIn", "", map[string]string{"content-type": "application/json", "x-better-iam": "1"}); empty.Code != 400 {
		t.Errorf("empty body: %d %s", empty.Code, empty.Body)
	}
	if health := serve(http.MethodGet, "/api/iam/health", "", nil); health.Code != 200 || health.Header().Get("Content-Type") != "application/json" {
		t.Errorf("health: %d %v", health.Code, health.Header())
	}
	// The session projection: a top-level session loses tokenHash and uniqueKey.
	f.createIdentity("alice@example.test", "Alice", "a strong alice password")
	signIn := serve(http.MethodPost, "/api/iam/auth/signIn", `{"tenantId":"`+f.rootTenantID()+`","email":"alice@example.test","password":"a strong alice password"}`, map[string]string{"content-type": "application/json", "x-better-iam": "1"})
	if signIn.Code != 200 || strings.Contains(signIn.Body.String(), "tokenHash") || strings.Contains(signIn.Body.String(), "uniqueKey") {
		t.Errorf("signIn: %d %s", signIn.Code, signIn.Body)
	}
	if !strings.HasPrefix(signIn.Header().Get("Set-Cookie"), "better-iam.session=") {
		t.Errorf("signIn cookie %q", signIn.Header().Get("Set-Cookie"))
	}
	// A bearer request never sets or clears the session cookie.
	token := jsString(member(member(parseJSONBytes(t, signIn.Body.Bytes()), "data"), "token"))
	signOut := serve(http.MethodPost, "/api/iam/auth/signOut", `{}`, map[string]string{"content-type": "application/json", "x-better-iam": "1", "authorization": "Bearer " + token})
	if signOut.Code != 200 || signOut.Header().Get("Set-Cookie") != "" {
		t.Errorf("bearer signOut: %d %q %s", signOut.Code, signOut.Header().Get("Set-Cookie"), signOut.Body)
	}
}

func parseJSONBytes(t *testing.T, data []byte) any {
	t.Helper()
	parsed, err := core.ParseJSON(data)
	if err != nil {
		t.Fatalf("invalid JSON %s: %v", data, err)
	}
	return parsed
}
