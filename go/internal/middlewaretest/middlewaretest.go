// Package middlewaretest is the shared scenario of tests/middleware.test.ts: the routes every framework integration
// mounts (written against the shared helpers) and the checks run against any of them (API mount, guards, page
// redirects, CSRF, step-up, in-process sign-in, refusals, sign-out).
package middlewaretest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/internal/orgfixture"
	"github.com/Better-IAM/better-iam/go/middleware"
)

// Origin is the deployment's origin (trusted by the IAM API and the guards).
const Origin = "http://localhost:3000"

// Fetch sends one request to the application under test.
type Fetch func(method, path string, header map[string]string, body string) *http.Response

// JSONHeaders are the headers of an IAM API call from the application's origin.
func JSONHeaders(extra map[string]string) map[string]string {
	header := map[string]string{"content-type": "application/json", "x-better-iam": "1", "origin": Origin}
	for name, value := range extra {
		header[name] = value
	}
	return header
}

// CookieOf is the session cookie (name=value) a response sets, "" when none.
func CookieOf(response *http.Response) string {
	for _, header := range response.Header.Values("Set-Cookie") {
		if strings.HasPrefix(header, "better-iam.session=") {
			pair, _, _ := strings.Cut(header, ";")
			return pair
		}
	}
	return ""
}

// Body reads a JSON response body.
func Body(t *testing.T, response *http.Response) map[string]any {
	t.Helper()
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("not a JSON object: %s", data)
	}
	return value
}

// ErrorCode is the code of a JSON error envelope.
func ErrorCode(t *testing.T, response *http.Response) string {
	t.Helper()
	failure, _ := Body(t, response)["error"].(map[string]any)
	code, _ := failure["code"].(string)
	return code
}

// Me is the /me route: the session's email and whether it may update identities.
func Me(ctx context.Context, iam *middleware.Helpers) (any, error) {
	session, err := iam.GetSession(ctx)
	if err != nil {
		return nil, err
	}
	canUpdate, err := iam.Can(ctx, "iam:identities:update", nil)
	if err != nil {
		return nil, err
	}
	var email any = core.Undefined
	if session != nil {
		email = session.Get("identity").(*core.Object).Get("email")
	}
	return core.NewObject("email", email, "canUpdate", canUpdate), nil
}

// Login is the /login route: signs in through the in-process client; the session it issued counts for the rest of
// the request.
func Login(ctx context.Context, iam *middleware.Helpers, tenantID string, body []byte) (any, error) {
	parsed, err := core.ParseJSON(body)
	if err != nil {
		return nil, err
	}
	input := core.NewObject("tenantId", tenantID)
	if object, ok := parsed.(*core.Object); ok {
		input.Assign(object)
	}
	if _, err := iam.Client().Call(ctx, "auth/signIn", input); err != nil {
		return nil, err
	}
	session, err := iam.GetSession(ctx)
	if err != nil {
		return nil, err
	}
	var email any = core.Undefined
	if session != nil {
		email = session.Get("identity").(*core.Object).Get("email")
	}
	return core.NewObject("signedInAs", email), nil
}

// Logout is the /logout route.
func Logout(ctx context.Context, iam *middleware.Helpers) (any, error) {
	if err := iam.SignOut(ctx); err != nil {
		return nil, err
	}
	session, err := iam.GetSession(ctx)
	if err != nil {
		return nil, err
	}
	return core.NewObject("signedOut", session == nil), nil
}

// Thrower is the /thrower route: a refusal returned from inside a route.
func Thrower(ctx context.Context, iam *middleware.Helpers) (any, error) {
	if err := iam.Require(ctx, "iam:identities:delete", nil); err != nil {
		return nil, err
	}
	return core.NewObject("unreachable", true), nil
}

// WriteJSON writes a JSON answer.
func WriteJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, core.MustStringify(value))
}

func expectStatus(t *testing.T, response *http.Response, status int) {
	t.Helper()
	if response.StatusCode != status {
		data, _ := io.ReadAll(response.Body)
		t.Fatalf("expected status %d, got %d: %s", status, response.StatusCode, data)
	}
}

func expectJSON(t *testing.T, response *http.Response, want string) {
	t.Helper()
	got := Body(t, response)
	var expected map[string]any
	if err := json.Unmarshal([]byte(want), &expected); err != nil {
		t.Fatal(err)
	}
	gotText, _ := json.Marshal(got)
	wantText, _ := json.Marshal(expected)
	if string(gotText) != string(wantText) {
		t.Fatalf("expected %s, got %s", wantText, gotText)
	}
}

// Scenario runs the shared checks against an application mounting the routes /me, /secure, /danger, /admin,
// /login, /logout and /thrower, with LoginPath /login and StepUpPath /verify.
func Scenario(t *testing.T, f *orgfixture.Fixture, call Fetch) {
	t.Helper()
	// The IAM API is answered by the integration.
	signIn := call("POST", "/api/iam/auth/signIn", JSONHeaders(nil), core.MustStringify(core.NewObject(
		"tenantId", f.TenantID, "email", "owner@acme.test", "password", orgfixture.OwnerPassword,
	)))
	expectStatus(t, signIn, 200)
	owner := CookieOf(signIn)
	if owner == "" {
		t.Fatal("sign-in did not set the session cookie")
	}
	if status := Body(t, call("GET", "/api/iam/health", nil, ""))["status"]; status != "ok" {
		t.Fatalf("health: %v", status)
	}

	// Guards: JSON envelope for API calls, redirects for page navigations.
	anonymous := call("GET", "/me", nil, "")
	expectStatus(t, anonymous, 401)
	if anonymous.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("cache-control: %q", anonymous.Header.Get("Cache-Control"))
	}
	expectJSON(t, anonymous, `{"error":{"code":"UNAUTHENTICATED","message":"A session is required"}}`)
	page := call("GET", "/me?tab=1", map[string]string{"accept": "text/html"}, "")
	expectStatus(t, page, 303)
	if location := page.Header.Get("Location"); location != "/login?next=%2Fme%3Ftab%3D1" {
		t.Fatalf("location: %q", location)
	}
	expectJSON(t, call("GET", "/me", map[string]string{"cookie": owner}, ""), `{"email":"owner@acme.test","canUpdate":true}`)

	// CSRF: cookie-authenticated unsafe requests to guarded routes must come from a trusted origin.
	danger := func(header map[string]string) *http.Response { return call("POST", "/danger", header, "") }
	crossSite := danger(map[string]string{"cookie": owner, "origin": "http://evil.test"})
	expectStatus(t, crossSite, 403)
	if code := ErrorCode(t, crossSite); code != "UNTRUSTED_ORIGIN" {
		t.Fatalf("cross-site: %s", code)
	}
	if code := ErrorCode(t, danger(map[string]string{"cookie": owner})); code != "CSRF_REJECTED" {
		t.Fatalf("no origin: %s", code)
	}
	expectStatus(t, danger(map[string]string{"cookie": owner, "origin": Origin}), 200) // the IAM origin is trusted
	expectStatus(t, danger(map[string]string{"cookie": owner, "sec-fetch-site": "same-origin"}), 200)
	token := strings.TrimPrefix(owner, "better-iam.session=")
	// Bearer credentials are not ambient, so no Origin check.
	expectStatus(t, danger(map[string]string{"authorization": "Bearer " + token, "origin": "http://evil.test"}), 200)

	// Step-up: a password-only session is refused (API) or sent to the step-up page (navigation).
	secure := call("GET", "/secure", map[string]string{"cookie": owner}, "")
	expectStatus(t, secure, 403)
	if code := ErrorCode(t, secure); code != "MFA_REQUIRED" {
		t.Fatalf("secure: %s", code)
	}
	secureNav := call("GET", "/secure", map[string]string{"cookie": owner, "accept": "text/html"}, "")
	if location := secureNav.Header.Get("Location"); location != "/verify?next=%2Fsecure&reason=mfa" {
		t.Fatalf("step-up location: %q", location)
	}

	// Authorization guard: the owner may update identities, a plain member may not.
	expectStatus(t, call("GET", "/admin", map[string]string{"cookie": owner}, ""), 200)
	f.Member("bob")
	bobLogin := call("POST", "/login", map[string]string{"content-type": "application/json"}, `{"email":"bob@acme.test","password":"a strong bob password"}`)
	setCookies := strings.Join(bobLogin.Header.Values("Set-Cookie"), "\n")
	bob := CookieOf(bobLogin)
	expectJSON(t, bobLogin, `{"signedInAs":"bob@acme.test"}`)
	if !regexp.MustCompile(`(?i)HttpOnly`).MatchString(setCookies) {
		t.Fatalf("the session cookie must be HttpOnly: %s", setCookies)
	}
	denied := call("GET", "/admin", map[string]string{"cookie": bob}, "")
	expectStatus(t, denied, 403)
	if code := ErrorCode(t, denied); code != "ACCESS_DENIED" {
		t.Fatalf("admin as bob: %s", code)
	}
	expectJSON(t, call("GET", "/me", map[string]string{"cookie": bob}, ""), `{"email":"bob@acme.test","canUpdate":false}`)

	// A refusal returned inside a route reaches the integration's error handling.
	thrown := call("GET", "/thrower", map[string]string{"cookie": bob}, "")
	expectStatus(t, thrown, 403)
	if code := ErrorCode(t, thrown); code != "ACCESS_DENIED" {
		t.Fatalf("thrower: %s", code)
	}

	// Sign-out ends the session server-side and clears the cookie.
	logout := call("POST", "/logout", map[string]string{"cookie": bob}, "")
	cleared := strings.Join(logout.Header.Values("Set-Cookie"), "\n")
	expectJSON(t, logout, `{"signedOut":true}`)
	if !regexp.MustCompile(`(?i)better-iam\.session=;.*Max-Age=0`).MatchString(cleared) {
		t.Fatalf("the session cookie was not cleared: %s", cleared)
	}
	expectStatus(t, call("GET", "/me", map[string]string{"cookie": bob}, ""), 401)
}

// Client is a Fetch over HTTP to base that does not follow redirects.
func Client(t *testing.T, base string) Fetch {
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return func(method, path string, header map[string]string, body string) *http.Response {
		t.Helper()
		var reader io.Reader
		if body != "" {
			reader = strings.NewReader(body)
		}
		request, err := http.NewRequest(method, base+path, reader)
		if err != nil {
			t.Fatal(err)
		}
		for name, value := range header {
			request.Header.Set(name, value)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = response.Body.Close() })
		return response
	}
}
