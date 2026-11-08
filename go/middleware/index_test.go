package middleware

// Ports of the `middleware helpers` tests of tests/middleware.test.ts, the `batches advisory checks per request` test,
// and the shared middleware check of tests/security-e15e8e-http.test.ts (Origin: null).

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/internal/orgfixture"
	"github.com/Better-IAM/better-iam/go/server"
)

func TestHelpersParseCookiesRecogniseDeletionsAndKeepRedirectsOnThisSite(t *testing.T) {
	if got := ParseCookieHeader("a=1; b=x%20y; a=2; junk").Entries(); !reflect.DeepEqual(got, [][2]string{{"a", "1"}, {"b", "x%20y"}}) {
		t.Fatalf("cookies %v", got)
	}
	if got := SetCookieSummary("s=abc; Path=/; HttpOnly"); !reflect.DeepEqual(got, &SetCookie{Name: "s", Value: "abc", Deleted: false}) {
		t.Fatalf("summary %+v", got)
	}
	if !SetCookieSummary("s=; Max-Age=0").Deleted {
		t.Fatal("Max-Age=0 deletes")
	}
	if !SetCookieSummary("s=; Expires=Thu, 01 Jan 1970 00:00:00 GMT").Deleted {
		t.Fatal("a past Expires deletes")
	}
	if SetCookieSummary("=x") != nil || SetCookieSummary("") != nil {
		t.Fatal("a header without a name has no summary")
	}
	if got := SafeRedirectPath("//evil.test"); got != "/" {
		t.Fatalf("redirect %q", got)
	}
	if got := SafeRedirectPath("/ok?x=1"); got != "/ok?x=1" {
		t.Fatalf("redirect %q", got)
	}
	for value, want := range map[string]string{
		"/a/../b":       "/b",
		"/.//evil.test": "/",
		"/a/%2e%2E/b":   "/b",
		"/a b?c d#e f":  "/a%20b?c%20d#e%20f",
		"/x\\y":         "/",
		"https://x":     "/",
		"/café":         "/caf%C3%A9",
		"/q?'":          "/q?%27",
		"/a/..":         "/",
		"/p?":           "/p",
	} {
		if got := SafeRedirectPath(value); got != want {
			t.Fatalf("SafeRedirectPath(%q) = %q, want %q", value, got, want)
		}
	}
	failure, err := CheckStepUp(core.NewObject("session", core.NewObject("mfa", true, "kind", "user")), StepUpRequirement{MFA: MfaFresh})
	if err != nil || failure != nil {
		t.Fatalf("fresh MFA session: %+v %v", failure, err)
	}
	failure, _ = CheckStepUp(core.NewObject("session", core.NewObject("mfa", true, "trustedDeviceId", "d")), StepUpRequirement{MFA: MfaFresh})
	if failure == nil || failure.Code != "MFA_REQUIRED" {
		t.Fatalf("remembered device: %+v", failure)
	}
	negative := -1.0
	if _, err := CheckStepUp(nil, StepUpRequirement{MaxAgeMs: &negative}); err == nil {
		t.Fatal("a non-positive maxAgeMs is a TypeError")
	}
	if _, err := CheckStepUp(nil, StepUpRequirement{MFA: "sometimes"}); err == nil {
		t.Fatal("an unknown mfa requirement is a TypeError")
	}
	recent := 60000.0
	failure, _ = CheckStepUp(core.NewObject("authenticatedAt", float64(1000), "method", "impersonation"), StepUpRequirement{MaxAgeMs: &recent}, 2000)
	if failure == nil || failure.Code != "IMPERSONATION_RESTRICTED" {
		t.Fatalf("impersonation: %+v", failure)
	}
	failure, _ = CheckStepUp(core.NewObject("authenticatedAt", float64(1000)), StepUpRequirement{MaxAgeMs: &recent}, 100000)
	if failure == nil || failure.Code != "RECENT_AUTH_REQUIRED" || failure.Reason != "recent" {
		t.Fatalf("stale sign-in: %+v", failure)
	}
	// POST navigations never redirect: a form post gets the JSON refusal.
	refusal, _ := RefusalOf(NewIamRequestError("UNAUTHENTICATED", "A session is required", 401))
	request := RefusalRequest{URL: mustURL(t, "http://x/app"), Header: http.Header{"Accept": {"text/html"}}, Method: "POST"}
	if answer := RefusalResponse(refusal, request, Pages{LoginPath: "/login"}); answer.Status != 401 || answer.Redirect != "" {
		t.Fatalf("POST refusal %+v", answer)
	}
	request.Method = "GET"
	if answer := RefusalResponse(refusal, request, Pages{LoginPath: "/login"}); answer.Redirect != "/login?next=%2Fapp" {
		t.Fatalf("GET refusal %+v", answer)
	}
	if got := WithQuery("/a?b=1", QueryParam{"c", "x y~*"}); got != "/a?b=1&c=x+y%7E*" {
		t.Fatalf("WithQuery %q", got)
	}
	if !UnderPath("/api/iam/x", "/api/iam/") || UnderPath("/api/iamx", "/api/iam") || !UnderPath("/anything", "/") {
		t.Fatal("UnderPath")
	}
}

func mustURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestCheckRequestOriginRefusesOpaqueOriginsEvenWhenATrustedEntryHasOne(t *testing.T) {
	trustedOrigins := []string{"capacitor://localhost", "https://admin.example.test"}
	request := func(origin string) OriginRequest {
		return OriginRequest{Method: "POST", URL: mustURL(t, "http://localhost:3000/api/transfer"), Header: http.Header{
			"Cookie": {"better-iam.session=abc"}, "Origin": {origin},
		}}
	}
	if refusal := CheckRequestOrigin(request("null"), trustedOrigins); refusal == nil || refusal.Code != "UNTRUSTED_ORIGIN" {
		t.Fatalf("null origin: %+v", refusal)
	}
	if refusal := CheckRequestOrigin(request("https://admin.example.test"), trustedOrigins); refusal != nil {
		t.Fatalf("trusted origin: %+v", refusal)
	}
	if refusal := CheckRequestOrigin(request("http://localhost:3000"), trustedOrigins); refusal != nil {
		t.Fatalf("own origin: %+v", refusal)
	}
	forwarded := request("https://app.example.test")
	forwarded.Header.Set("X-Forwarded-Host", "app.example.test, proxy")
	forwarded.Header.Set("X-Forwarded-Proto", "https")
	if refusal := CheckRequestOrigin(forwarded, nil); refusal != nil {
		t.Fatalf("forwarded origin: %+v", refusal)
	}
	safe := request("http://evil.test")
	safe.Method = "get"
	if CheckRequestOrigin(safe, nil) != nil {
		t.Fatal("safe methods are not checked")
	}
	anonymous := request("http://evil.test")
	anonymous.Header.Del("Cookie")
	if CheckRequestOrigin(anonymous, nil) != nil {
		t.Fatal("requests without a session cookie are not checked")
	}
}

// countingIAM counts authorizeMany calls and the checks they carried.
type countingIAM struct {
	*ServerIAM
	calls  atomic.Int32
	checks atomic.Int32
}

func (c *countingIAM) AuthorizeMany(ctx context.Context, request server.BatchAuthorizationRequest) (*core.Object, error) {
	c.calls.Add(1)
	c.checks.Add(int32(len(request.Checks)))
	return c.ServerIAM.AuthorizeMany(ctx, request)
}

func TestHelpersBatchAdvisoryChecksPerRequest(t *testing.T) {
	f := orgfixture.New(t, nil)
	counting := &countingIAM{ServerIAM: Server(f.IAM)}
	token := f.OwnerSignIn().Token
	helpers := NewHelpers(func(context.Context) (IAM, error) { return counting, nil }, RequestBinding{
		URL: mustURL(t, "http://127.0.0.1/checks"), Header: http.Header{"Cookie": {"better-iam.session=" + token}},
	}, HelperOptions{})
	// The session is resolved first, so the three checks below queue together before the batch is sent.
	if _, err := helpers.GetSession(f.Ctx); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var flushes []func()
	queued := make(chan struct{}, 3)
	previous := scheduleFlush
	scheduleFlush = func(flush func()) {
		mu.Lock()
		defer mu.Unlock()
		flushes = append(flushes, flush)
	}
	t.Cleanup(func() { scheduleFlush = previous })
	answers := make([]bool, 3)
	errs := make([]error, 3)
	var group sync.WaitGroup
	for index, action := range []string{"iam:identities:read", "iam:identities:update", "iam:identities:read"} {
		group.Add(1)
		go func() {
			defer group.Done()
			queued <- struct{}{}
			answers[index], errs[index] = helpers.Can(f.Ctx, action, nil)
		}()
	}
	for range 3 {
		<-queued
	}
	// Wait until the two distinct checks are queued (the repeated one shares the first answer).
	for {
		helpers.mu.Lock()
		pending := len(helpers.answers)
		helpers.mu.Unlock()
		if pending == 2 {
			break
		}
	}
	mu.Lock()
	scheduled := append([]func(){}, flushes...)
	mu.Unlock()
	for _, flush := range scheduled {
		flush()
	}
	group.Wait()
	for index := range errs {
		if errs[index] != nil {
			t.Fatal(errs[index])
		}
	}
	if !reflect.DeepEqual(answers, []bool{true, true, true}) {
		t.Fatalf("answers %v", answers)
	}
	if counting.calls.Load() != 1 || counting.checks.Load() != 2 {
		t.Fatalf("authorizeMany calls %d with %d checks", counting.calls.Load(), counting.checks.Load())
	}
	// A repeated check within the request is answered from memory.
	scheduleFlush = previous
	if allowed, err := helpers.Can(f.Ctx, "iam:identities:update", nil); err != nil || !allowed {
		t.Fatalf("memoized: %v %v", allowed, err)
	}
	if counting.calls.Load() != 1 {
		t.Fatalf("authorizeMany calls %d", counting.calls.Load())
	}
	// Signed out: every check is false without a call.
	anonymous := NewHelpers(func(context.Context) (IAM, error) { return counting, nil }, RequestBinding{URL: mustURL(t, "http://127.0.0.1/")}, HelperOptions{})
	if allowed, err := anonymous.Can(f.Ctx, "iam:identities:read", nil); err != nil || allowed {
		t.Fatalf("anonymous: %v %v", allowed, err)
	}
	results, err := anonymous.Authorize(f.Ctx, []Check{{Action: "iam:identities:read"}})
	if err != nil || len(results) != 1 || results[0].Reason != "UNAUTHENTICATED" || results[0].Resource != (ResourceRef{Type: "iam", ID: ""}) {
		t.Fatalf("anonymous authorize: %+v %v", results, err)
	}
	results, err = helpers.Authorize(f.Ctx, []Check{{Action: "iam:identities:read"}, {Action: "documents:read", Resource: &ResourceRef{Type: "document", ID: "x"}}})
	if err != nil || len(results) != 2 || !results[0].Allowed || results[0].Resource.ID != f.TenantID {
		t.Fatalf("authorize: %+v %v", results, err)
	}
}
