package client

// Ports of tests/client.test.ts and the stubbed parts of tests/client-hooks.test.ts: the transport contract, bearer
// shapes, credential-only methods, structured errors, the plugin transport, the session-ending hook, rate-limit
// retries and request ids.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

type recorded struct {
	url     string
	method  string
	headers http.Header
	body    string
	ctx     context.Context
}

// stub is a Fetch implementation answering from a queue (the last answer repeats) and recording each request.
type stub struct {
	mu      sync.Mutex
	answers []func() *http.Response
	calls   []recorded
}

func answer(status int, body string, headers ...string) func() *http.Response {
	return func() *http.Response {
		header := http.Header{"Content-Type": {"application/json"}}
		for index := 0; index+1 < len(headers); index += 2 {
			header.Set(headers[index], headers[index+1])
		}
		return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}
	}
}

func failure(code string, status int, extra string, headers ...string) func() *http.Response {
	body := `{"error":{"code":"` + code + `","message":"` + code + `"` + extra + `}}`
	return answer(status, body, headers...)
}

func (s *stub) fetch(request *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(request.Body)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, recorded{url: request.URL.String(), method: request.Method, headers: request.Header.Clone(), body: string(body), ctx: request.Context()})
	if len(s.answers) == 0 {
		return nil, errors.New("no answer queued")
	}
	next := s.answers[0]
	if len(s.answers) > 1 {
		s.answers = s.answers[1:]
	}
	return next(), nil
}

func (s *stub) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *stub) last() recorded {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[len(s.calls)-1]
}

func (s *stub) call(index int) recorded {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[index]
}

func newStub(answers ...func() *http.Response) *stub { return &stub{answers: answers} }

func mustClient(t *testing.T, options Options) *Client {
	t.Helper()
	c, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func jsonOf(t *testing.T, text string) any {
	t.Helper()
	var value any
	if err := json.Unmarshal([]byte(text), &value); err != nil {
		t.Fatalf("invalid JSON %q: %v", text, err)
	}
	return value
}

func expectJSON(t *testing.T, got string, want string) {
	t.Helper()
	if !reflect.DeepEqual(jsonOf(t, got), jsonOf(t, want)) {
		t.Fatalf("JSON = %s, want %s", got, want)
	}
}

func clientError(t *testing.T, err error, code string, status int) *IamClientError {
	t.Helper()
	var failure *IamClientError
	if !errors.As(err, &failure) {
		t.Fatalf("expected an IamClientError %s, got %v", code, err)
	}
	if failure.Code != code || (status >= 0 && failure.Status != status) {
		t.Fatalf("expected %s/%d, got %s/%d (%s)", code, status, failure.Code, failure.Status, failure.Message)
	}
	return failure
}

func stringify(t *testing.T, value any) string {
	t.Helper()
	text, _, err := core.Stringify(value)
	if err != nil {
		t.Fatal(err)
	}
	return text
}

func TestClientSendsTheServerJSONContractWithMandatoryCSRFHeaders(t *testing.T) {
	fetcher := newStub(answer(200, `{"data":{"token":"new-token"}}`))
	c := mustClient(t, Options{
		BaseURL: "https://app.example.com",
		Fetch:   fetcher.fetch,
		Headers: http.Header{"X-Trace-Id": {"trace-1"}, "X-Better-Iam": {"wrong"}, "Content-Type": {"text/plain"}},
	})
	input := core.NewObject("tenantId", "tenant-1", "email", "a@example.com", "password", "a-long-password")
	result, err := c.Request(context.Background(), "auth/signIn", input)
	if err != nil {
		t.Fatal(err)
	}
	expectJSON(t, stringify(t, result), `{"token":"new-token"}`)
	call := fetcher.call(0)
	if call.url != "https://app.example.com/api/iam/auth/signIn" || call.method != http.MethodPost {
		t.Fatalf("request %s %s", call.method, call.url)
	}
	expectJSON(t, call.body, `{"tenantId":"tenant-1","email":"a@example.com","password":"a-long-password"}`)
	if call.headers.Get("content-type") != "application/json" || call.headers.Get("x-better-iam") != "1" ||
		call.headers.Get("x-trace-id") != "trace-1" || call.headers.Get("authorization") != "" {
		t.Fatalf("headers %v", call.headers)
	}
	// The typed method sends its request type as the body.
	if _, err := c.Auth.SignIn(context.Background(), apitypes.AuthSignInInput{TenantID: "tenant-1", Email: "a@example.com", Password: "a-long-password"}); err == nil {
		t.Fatal("a token without a session must not decode as a sign-in result")
	}
	expectJSON(t, fetcher.last().body, `{"tenantId":"tenant-1","email":"a@example.com","password":"a-long-password"}`)
}

func TestClientReadsTheCurrentBearerTokenAtEachRequestAndSupportsCancellation(t *testing.T) {
	token := "first-token-abcdefghijklmnop"
	fetcher := newStub(answer(200, `{"data":{"identity":{"id":"user-1"}}}`))
	c := mustClient(t, Options{
		BaseURL:  "https://app.example.com",
		BasePath: "/custom/iam",
		Fetch:    fetcher.fetch,
		TokenFunc: func(context.Context) (string, bool, error) {
			return token, true, nil
		},
	})
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), struct{ name string }{"trace"}, "x"))
	defer cancel()
	if _, err := Call[any](ctx, c, "auth/getSession", nil, CallOptions{Headers: http.Header{"X-Trace-Id": {"trace-2"}}}); err != nil {
		t.Fatal(err)
	}
	token = "second-token-abcdefghijklmnop"
	if _, err := Call[any](context.Background(), c, "auth/getSession", nil); err != nil {
		t.Fatal(err)
	}
	first, second := fetcher.call(0), fetcher.call(1)
	if first.url != "https://app.example.com/custom/iam/auth/getSession" {
		t.Fatalf("url %s", first.url)
	}
	if first.ctx.Value(struct{ name string }{"trace"}) != "x" || first.headers.Get("x-trace-id") != "trace-2" {
		t.Fatal("the call's context and headers were not passed on")
	}
	expectJSON(t, first.body, `{}`)
	if !strings.Contains(first.headers.Get("authorization"), "first-token") || !strings.Contains(second.headers.Get("authorization"), "second-token") {
		t.Fatalf("authorization %q / %q", first.headers.Get("authorization"), second.headers.Get("authorization"))
	}
	// A cancelled call fails with the context's cause.
	cancelled, stop := context.WithCancelCause(context.Background())
	reason := errors.New("search cancelled")
	stop(reason)
	blocking := mustClient(t, Options{BaseURL: "https://app.example.com", Fetch: func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	}})
	if _, err := blocking.Request(cancelled, "auth/getSession", nil); !errors.Is(err, reason) {
		t.Fatalf("cancelled call: %v", err)
	}
}

func segment(length int) string {
	return strings.Repeat("aB3_-", length/5+1)[:length]
}

func TestClientSendsPrefixedTokensAndSessionJWTsAndRefusesOtherShapes(t *testing.T) {
	var token string
	hasToken := false
	fetcher := newStub(answer(200, `{"data":{"identity":{"id":"user-1"}}}`))
	c := mustClient(t, Options{
		BaseURL: "https://app.example.com",
		Fetch:   fetcher.fetch,
		TokenFunc: func(context.Context) (string, bool, error) {
			return token, hasToken, nil
		},
	})
	prefixed := "biam_sts_" + segment(43) + "AbC12_"
	if len(prefixed) != 58 {
		t.Fatalf("prefixed length %d", len(prefixed))
	}
	jwt := segment(40) + "." + segment(300) + "." + segment(86)
	// The largest JWT the server issues (4096 characters) still passes.
	largest := segment(1024) + "." + segment(4096-2048-2) + "." + segment(1024)
	if len(largest) != 4096 {
		t.Fatalf("largest length %d", len(largest))
	}
	hasToken = true
	for _, value := range []string{prefixed, jwt, largest} {
		token = value
		if _, err := c.Request(context.Background(), "auth/getSession", nil); err != nil {
			t.Fatal(err)
		}
		if got := fetcher.last().headers.Get("authorization"); got != "Bearer "+value {
			t.Fatalf("authorization %q", got)
		}
	}
	token = jwt
	fetcher.answers = []func() *http.Response{answer(200, `{"data":{"arn":"iam::t:user/u","tenantId":"t","identityId":"u","sessionKind":"session-token"}}`)}
	identity, err := c.Sts.GetCallerIdentity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if identity.SessionKind != "session-token" {
		t.Fatalf("caller identity %+v", identity)
	}
	if fetcher.last().url != "https://app.example.com/api/iam/sts/getCallerIdentity" {
		t.Fatalf("url %s", fetcher.last().url)
	}
	expectJSON(t, fetcher.last().body, `{}`)

	calls := fetcher.count()
	for _, value := range []string{
		"",
		"short",
		segment(16) + " ",
		"Bearer abcdefghijklmnopqrstuvwxyz",
		segment(10) + "." + segment(10),
		segment(10) + "." + segment(10) + "." + segment(10) + "." + segment(10),
		segment(10) + ".." + segment(10),
		segment(10) + "." + segment(10) + ".",
		segment(10) + "." + segment(1) + "." + segment(10),
		segment(10) + "." + segment(10) + "." + segment(10) + "=",
		segment(1025) + "." + segment(10) + "." + segment(10),
		segment(1024) + "." + segment(2049) + "." + segment(1024),
		segment(513),
	} {
		token = value
		_, err := c.Request(context.Background(), "auth/getSession", nil)
		clientError(t, err, "INVALID_TOKEN", 0)
	}
	if fetcher.count() != calls {
		t.Fatal("a refused token reached the network")
	}
	// A static token is checked the same way.
	static := mustClient(t, Options{BaseURL: "https://app.example.com", Fetch: fetcher.fetch, Token: "short"})
	_, err = static.Request(context.Background(), "auth/getSession", nil)
	clientError(t, err, "INVALID_TOKEN", 0)
}

func TestClientSendsNoBodyForCredentialOnlyMethodsOutsideAuth(t *testing.T) {
	fetcher := newStub(
		answer(200, `{"data":{"arn":"iam::t:user/u","tenantId":"t","identityId":"u","sessionKind":"sts"}}`),
		answer(200, `{"data":[]}`),
		answer(200, `{"data":[]}`),
	)
	c := mustClient(t, Options{BaseURL: "https://app.example.com", Fetch: fetcher.fetch})
	ctx := context.WithValue(context.Background(), struct{ name string }{"call"}, "marker")
	if _, err := c.Sts.GetCallerIdentity(ctx, CallOptions{Headers: http.Header{"X-Trace": {"1"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Links.List(ctx, CallOptions{Headers: http.Header{"X-Trace": {"2"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Clearances.Templates(ctx, CallOptions{Headers: http.Header{"X-Trace": {"3"}}}); err != nil {
		t.Fatal(err)
	}
	for index, path := range []string{"sts/getCallerIdentity", "links/list", "clearances/templates"} {
		call := fetcher.call(index)
		if call.url != "https://app.example.com/api/iam/"+path {
			t.Fatalf("url %s", call.url)
		}
		expectJSON(t, call.body, `{}`)
		if call.ctx.Value(struct{ name string }{"call"}) != "marker" || call.headers.Get("x-trace") != string(rune('1'+index)) {
			t.Fatalf("%s: options not applied", path)
		}
	}
}

func TestClientOmitsAuthenticatedCredentialsWhileRetainingPublicInvitationTokens(t *testing.T) {
	fetcher := newStub(answer(200, `{"data":{}}`))
	c := mustClient(t, Options{BaseURL: "https://app.example.com", Fetch: fetcher.fetch})
	ctx := context.Background()
	_, _ = c.Tenants.Create(ctx, apitypes.TenantsCreateInput{ParentID: "root", Name: "Organization", Type: "organization", OwnerEmail: "owner@example.test"})
	_, _ = c.Tenants.AcceptInvitation(ctx, apitypes.TenantsAcceptInvitationInput{TenantID: "org", Token: "invitation-token", Name: "Owner", Password: "long-password"})
	_, _ = c.Auth.BeginMfa(ctx, nil)
	_, _ = c.Auth.BeginMfa(ctx, &MfaChallenge{TenantID: "org", Challenge: "restricted-challenge"})
	_, _ = c.Auth.ConfirmMfa(ctx, ConfirmMfaInput{Code: "123456"})
	_, _ = c.Auth.ConfirmMfa(ctx, ConfirmMfaInput{Credential: &MfaChallenge{TenantID: "root", Challenge: "restricted-challenge"}, Code: "123456"})
	expectJSON(t, fetcher.call(0).body, `{"parentId":"root","type":"organization","name":"Organization","ownerEmail":"owner@example.test"}`)
	if body := jsonOf(t, fetcher.call(1).body).(map[string]any); body["token"] != "invitation-token" {
		t.Fatalf("acceptInvitation body %v", body)
	}
	expectJSON(t, fetcher.call(2).body, `{}`)
	if body := jsonOf(t, fetcher.call(3).body).(map[string]any); body["challenge"] != "restricted-challenge" {
		t.Fatalf("beginMfa body %v", body)
	}
	expectJSON(t, fetcher.call(4).body, `{"code":"123456"}`)
	expectJSON(t, fetcher.call(5).body, `{"credential":{"tenantId":"root","challenge":"restricted-challenge"},"code":"123456"}`)
	for _, call := range fetcher.calls {
		if call.headers.Get("authorization") != "" {
			t.Fatal("no credential was configured, none may be sent")
		}
	}
}

func TestClientRetainsStructuredErrorsAndRejectsMalformedResponses(t *testing.T) {
	fetcher := newStub(
		answer(403, `{"error":{"code":"MFA_REQUIRED","message":"Use MFA"}}`),
		answer(502, `<html>private upstream details</html>`),
		answer(200, `{"wrong":"shape"}`),
		answer(503, `{"data":null}`),
		answer(400, `{"error":{"code":1,"message":"x"}}`),
		answer(200, `[1,2]`),
		answer(200, `null`),
		answer(200, `{"data":null}`),
	)
	c := mustClient(t, Options{BaseURL: "https://app.example.com", Fetch: fetcher.fetch})
	ctx := context.Background()
	_, err := c.Request(ctx, "auth/getSession", nil)
	if failure := clientError(t, err, "MFA_REQUIRED", 403); failure.Message != "Use MFA" {
		t.Fatalf("message %q", failure.Message)
	}
	_, err = c.Request(ctx, "auth/getSession", nil)
	if failure := clientError(t, err, "INVALID_RESPONSE", 502); strings.Contains(failure.Message, "private") {
		t.Fatal("the response body was echoed")
	}
	_, err = c.Request(ctx, "auth/getSession", nil)
	clientError(t, err, "INVALID_RESPONSE", 200)
	_, err = c.Request(ctx, "auth/getSession", nil)
	clientError(t, err, "HTTP_ERROR", 503)
	_, err = c.Request(ctx, "auth/getSession", nil)
	if failure := clientError(t, err, "INVALID_RESPONSE", 400); failure.Message != "The IAM server returned an invalid error response" {
		t.Fatalf("message %q", failure.Message)
	}
	_, err = c.Request(ctx, "auth/getSession", nil)
	clientError(t, err, "INVALID_RESPONSE", 200)
	_, err = c.Request(ctx, "auth/getSession", nil)
	clientError(t, err, "INVALID_RESPONSE", 200)
	if data, err := c.Request(ctx, "auth/getSession", nil); err != nil || data != nil {
		t.Fatalf("null data: %v %v", data, err)
	}
}

func TestClientProvidesAuthorizeAndPluginTransportsWhileRejectingTraversal(t *testing.T) {
	fetcher := newStub(answer(200, `{"data":{"allowed":true,"reason":"Allowed by policy","matchedStatements":[]}}`))
	c := mustClient(t, Options{BaseURL: "https://app.example.com", Fetch: fetcher.fetch})
	ctx := context.Background()
	decision, err := c.Authorize(ctx, apitypes.AuthorizeInput{TenantID: "org", Action: "documents:read", Resource: apitypes.AuthorizeInputResource{Type: "document", ID: "one"}})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatalf("decision %+v", decision)
	}
	if _, err := c.Request(ctx, "plugins/reporting/summary", core.NewObject("tenantId", "org")); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(fetcher.call(0).url, "/authorize") || !strings.HasSuffix(fetcher.call(1).url, "/plugins/reporting/summary") {
		t.Fatalf("urls %s %s", fetcher.call(0).url, fetcher.call(1).url)
	}
	for _, path := range []string{"../secrets", "https://attacker.example", "", "plugins//x", "auth/then", "constructor", "__proto__/x", "1group/x"} {
		_, err := c.Request(ctx, path, nil)
		clientError(t, err, "INVALID_PATH", 0)
	}
	if fetcher.count() != 2 {
		t.Fatal("a refused path reached the network")
	}
	if c.String() != "BetterIamClient" {
		t.Fatal(c.String())
	}
}

func TestClientValidatesItsConfiguration(t *testing.T) {
	for _, tc := range []struct {
		options Options
		message string
	}{
		{Options{}, "baseURL is required outside a browser"},
		{Options{BaseURL: "not a url"}, "baseURL must be an absolute HTTP(S) URL"},
		{Options{BaseURL: "http://"}, "baseURL must be an absolute HTTP(S) URL"},
		{Options{BaseURL: "ftp://example.com"}, "baseURL must be an HTTP(S) URL without credentials, query, or fragment"},
		{Options{BaseURL: "https://user:pw@example.com"}, "baseURL must be an HTTP(S) URL without credentials, query, or fragment"},
		{Options{BaseURL: "https://example.com/?a=1"}, "baseURL must be an HTTP(S) URL without credentials, query, or fragment"},
		{Options{BaseURL: "https://example.com/#top"}, "baseURL must be an HTTP(S) URL without credentials, query, or fragment"},
		{Options{BaseURL: "https://example.com", BasePath: "api/iam"}, "basePath must be an absolute path without a trailing slash"},
		{Options{BaseURL: "https://example.com", BasePath: "/api/iam/"}, "basePath must be an absolute path without a trailing slash"},
		{Options{BaseURL: "https://example.com", BasePath: "/api/i am"}, "basePath must be an absolute path without a trailing slash"},
	} {
		_, err := New(tc.options)
		if failure := clientError(t, err, "INVALID_CONFIG", 0); failure.Message != tc.message {
			t.Errorf("%+v: %q, want %q", tc.options, failure.Message, tc.message)
		}
	}
	// The origin drops the path, the default port and the host's case.
	fetcher := newStub(answer(200, `{"data":1}`))
	c := mustClient(t, Options{BaseURL: "HTTPS://App.Example.com:443/ignored/path", Fetch: fetcher.fetch})
	if _, err := c.Request(context.Background(), "auth/getSession", nil); err != nil {
		t.Fatal(err)
	}
	if fetcher.last().url != "https://app.example.com/api/iam/auth/getSession" {
		t.Fatalf("url %s", fetcher.last().url)
	}
	// Input that is not JSON never leaves the client.
	_, err := c.Request(context.Background(), "auth/getSession", map[string]any{"bad": make(chan int)})
	clientError(t, err, "INVALID_INPUT", 0)
}

func TestClientReportsLapsedSessionsOnceThroughOnUnauthenticated(t *testing.T) {
	fetcher := newStub(
		failure("UNAUTHENTICATED", 401, ""),
		failure("INVALID_CREDENTIALS", 401, ""),
		answer(200, `{"data":{"identity":{"id":"usr_1"}}}`),
	)
	var calls int
	c := mustClient(t, Options{BaseURL: "https://app.example.com", Fetch: fetcher.fetch, OnUnauthenticated: func(err *IamClientError) {
		calls++
		panic("hook failure for " + err.Code)
	}})
	ctx := context.Background()
	_, err := c.Request(ctx, "auth/getSession", nil)
	clientError(t, err, "UNAUTHENTICATED", 401)
	if calls != 1 {
		t.Fatalf("hook calls %d", calls)
	}
	// A wrong password is the caller's problem, not a lapsed session.
	_, err = c.Request(ctx, "auth/signIn", core.NewObject("tenantId", "t", "email", "a@example.com", "password", "wrong"))
	clientError(t, err, "INVALID_CREDENTIALS", 401)
	if calls != 1 {
		t.Fatalf("hook calls %d", calls)
	}
	data, err := c.Request(ctx, "auth/getSession", nil)
	if err != nil {
		t.Fatal(err)
	}
	expectJSON(t, stringify(t, data), `{"identity":{"id":"usr_1"}}`)
}

func TestClientTreatsANetworkMismatchAsEndedButNotSignInOrStepUpRefusals(t *testing.T) {
	fetcher := newStub(
		failure("SESSION_NETWORK_MISMATCH", 401, ""),
		failure("MFA_REQUIRED", 403, ""),
		failure("EMAIL_UNVERIFIED", 403, ""),
		failure("IP_BLOCKED", 403, ""),
		failure("INVALID_CREDENTIALS", 401, ""),
	)
	var seen []string
	c := mustClient(t, Options{BaseURL: "https://app.example.com", Fetch: fetcher.fetch, OnUnauthenticated: func(err *IamClientError) {
		seen = append(seen, err.Code)
	}})
	ctx := context.Background()
	_, err := c.Request(ctx, "auth/getSession", nil)
	clientError(t, err, "SESSION_NETWORK_MISMATCH", 401)
	for _, code := range []string{"MFA_REQUIRED", "EMAIL_UNVERIFIED", "IP_BLOCKED"} {
		_, err := c.Request(ctx, "auth/getSession", nil)
		clientError(t, err, code, -1)
	}
	_, err = c.Request(ctx, "auth/signIn", core.NewObject("tenantId", "t"))
	clientError(t, err, "INVALID_CREDENTIALS", 401)
	if !reflect.DeepEqual(seen, []string{"SESSION_NETWORK_MISMATCH"}) {
		t.Fatalf("hook saw %v", seen)
	}
}

// fakeWait replaces the retry wait: it records each wait and returns at once (or the context's cause).
func fakeWait(t *testing.T) *[]float64 {
	t.Helper()
	var waits []float64
	previous := wait
	wait = func(ctx context.Context, ms float64) error {
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		waits = append(waits, ms)
		return nil
	}
	t.Cleanup(func() { wait = previous })
	return &waits
}

func TestClientRetriesARateLimitedCallOnceWhenTheWaitIsShortEnough(t *testing.T) {
	waits := fakeWait(t)
	fetcher := newStub(
		failure("RATE_LIMITED", 429, `,"retryAfterMs":1500`),
		answer(200, `{"data":{"identity":{"id":"usr_1"}}}`),
		failure("RATE_LIMITED", 429, `,"retryAfterMs":60000`),
		failure("RATE_LIMITED", 429, `,"retryAfterMs":1000`),
		failure("RATE_LIMITED", 429, `,"retryAfterMs":1000`),
	)
	c := mustClient(t, Options{BaseURL: "https://app.example.com", Fetch: fetcher.fetch, RetryRateLimited: true, RetryMaxWaitMs: 2_000})
	ctx := context.Background()
	data, err := c.Request(ctx, "auth/getSession", nil)
	if err != nil {
		t.Fatal(err)
	}
	expectJSON(t, stringify(t, data), `{"identity":{"id":"usr_1"}}`)
	if fetcher.count() != 2 || !reflect.DeepEqual(*waits, []float64{1500}) {
		t.Fatalf("calls %d, waits %v", fetcher.count(), *waits)
	}
	// A wait beyond the cap surfaces the error unchanged; a second refusal after the retry does too.
	_, err = c.Request(ctx, "auth/getSession", nil)
	if failure := clientError(t, err, "RATE_LIMITED", 429); failure.RetryAfterMs == nil || *failure.RetryAfterMs != 60_000 {
		t.Fatalf("retryAfterMs %v", failure.RetryAfterMs)
	}
	if fetcher.count() != 3 {
		t.Fatalf("calls %d", fetcher.count())
	}
	_, err = c.Request(ctx, "auth/getSession", nil)
	clientError(t, err, "RATE_LIMITED", 429)
	if fetcher.count() != 5 {
		t.Fatalf("calls %d", fetcher.count())
	}
	// Off by default.
	plain := mustClient(t, Options{BaseURL: "https://app.example.com", Fetch: newStub(failure("RATE_LIMITED", 429, `,"retryAfterMs":10`)).fetch})
	_, err = plain.Request(ctx, "auth/getSession", nil)
	clientError(t, err, "RATE_LIMITED", 429)
	// The default cap is five seconds; the header's seconds count when the body has no retryAfterMs.
	headed := newStub(failure("RATE_LIMITED", 429, "", "Retry-After", "4"), answer(200, `{"data":1}`))
	defaulted := mustClient(t, Options{BaseURL: "https://app.example.com", Fetch: headed.fetch, RetryRateLimited: true})
	if _, err := defaulted.Request(ctx, "auth/getSession", nil); err != nil {
		t.Fatal(err)
	}
	if (*waits)[len(*waits)-1] != 4_000 {
		t.Fatalf("waits %v", *waits)
	}
}

func TestClientStopsWaitingToRetryWhenTheCallIsCancelled(t *testing.T) {
	fetcher := newStub(failure("RATE_LIMITED", 429, `,"retryAfterMs":4000`))
	c := mustClient(t, Options{BaseURL: "https://app.example.com", Fetch: fetcher.fetch, RetryRateLimited: true})
	// Cancelled during the wait: the call returns at once with the context's cause and sends nothing more.
	reason := errors.New("search cancelled")
	ctx, cancel := context.WithCancelCause(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := c.Request(ctx, "auth/getSession", nil)
		done <- err
	}()
	for fetcher.count() == 0 {
		select {
		case err := <-done:
			t.Fatalf("returned before the wait: %v", err)
		default:
		}
	}
	cancel(reason)
	if err := <-done; !errors.Is(err, reason) {
		t.Fatalf("cancelled wait: %v", err)
	}
	if fetcher.count() != 1 {
		t.Fatalf("calls %d", fetcher.count())
	}
	// Without a cause, the error is context.Canceled.
	plain, stop := context.WithCancel(context.Background())
	go func() {
		_, err := c.Request(plain, "auth/getSession", nil)
		done <- err
	}()
	for fetcher.count() == 1 {
	}
	stop()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled wait: %v", err)
	}
	// A context already ended when the refusal arrives never starts the wait.
	early, end := context.WithCancelCause(context.Background())
	preempting := mustClient(t, Options{BaseURL: "https://app.example.com", RetryRateLimited: true, Fetch: func(request *http.Request) (*http.Response, error) {
		end(reason)
		return failure("RATE_LIMITED", 429, `,"retryAfterMs":4000`)(), nil
	}})
	if _, err := preempting.Request(early, "auth/getSession", nil); !errors.Is(err, reason) {
		t.Fatalf("pre-empted wait: %v", err)
	}
	// A context that never ends leaves the retry unchanged.
	waits := fakeWait(t)
	retried := newStub(failure("RATE_LIMITED", 429, `,"retryAfterMs":4000`), answer(200, `{"data":{"identity":{"id":"usr_1"}}}`))
	kept := mustClient(t, Options{BaseURL: "https://app.example.com", Fetch: retried.fetch, RetryRateLimited: true})
	if _, err := kept.Request(context.Background(), "auth/getSession", nil); err != nil {
		t.Fatal(err)
	}
	if retried.count() != 2 || !reflect.DeepEqual(*waits, []float64{4000}) {
		t.Fatalf("calls %d waits %v", retried.count(), *waits)
	}
}

func TestClientTagsRequestsWithRequestIDsAndCarriesThemOnErrors(t *testing.T) {
	fetcher := newStub(answer(200, `{"data":{"identity":{"id":"usr_1"}}}`), failure("ACCESS_DENIED", 403, ""))
	ids := []string{"req-one", "req-two"}
	c := mustClient(t, Options{BaseURL: "https://app.example.com", Fetch: fetcher.fetch, RequestID: func() string {
		next := ids[0]
		ids = ids[1:]
		return next
	}})
	ctx := context.Background()
	if _, err := c.Request(ctx, "auth/getSession", nil); err != nil {
		t.Fatal(err)
	}
	if fetcher.call(0).headers.Get("x-request-id") != "req-one" {
		t.Fatalf("request id %q", fetcher.call(0).headers.Get("x-request-id"))
	}
	_, err := c.Request(ctx, "auth/getSession", nil)
	if failure := clientError(t, err, "ACCESS_DENIED", 403); failure.RequestID != "req-two" {
		t.Fatalf("request id %q", failure.RequestID)
	}
	// Generated identifiers are plain tokens the server accepts.
	generated := newStub(answer(200, `{"data":{}}`))
	if _, err := mustClient(t, Options{BaseURL: "https://app.example.com", Fetch: generated.fetch, GenerateRequestID: true}).Request(ctx, "auth/getSession", nil); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`).MatchString(generated.last().headers.Get("x-request-id")) {
		t.Fatalf("generated id %q", generated.last().headers.Get("x-request-id"))
	}
	// An invalid custom identifier is refused before anything is sent.
	_, err = mustClient(t, Options{BaseURL: "https://app.example.com", Fetch: generated.fetch, RequestID: func() string { return "not valid!" }}).Request(ctx, "auth/getSession", nil)
	clientError(t, err, "INVALID_CONFIG", 0)
	if generated.count() != 1 {
		t.Fatal("an invalid request id reached the network")
	}
}

func TestClientKeepsWrongRegionDetails(t *testing.T) {
	fetcher := newStub(
		failure("WRONG_REGION", 421, `,"region":"eu-west-1","location":"https://eu.example.com/sign-in"`),
		failure("WRONG_REGION", 421, `,"region":"eu-west-1","location":"javascript:alert(1)"`),
	)
	c := mustClient(t, Options{BaseURL: "https://app.example.com", Fetch: fetcher.fetch})
	_, err := c.Request(context.Background(), "auth/signIn", nil)
	if failure := clientError(t, err, "WRONG_REGION", 421); failure.Region != "eu-west-1" || failure.Location != "https://eu.example.com/sign-in" {
		t.Fatalf("details %+v", failure)
	}
	_, err = c.Request(context.Background(), "auth/signIn", nil)
	if failure := clientError(t, err, "WRONG_REGION", 421); failure.Location != "" {
		t.Fatalf("an unsafe location was kept: %q", failure.Location)
	}
}

func TestClientEncodesBodiesAsJavaScriptDoes(t *testing.T) {
	fetcher := newStub(answer(200, `{"data":{}}`))
	c := mustClient(t, Options{BaseURL: "https://app.example.com", Fetch: fetcher.fetch})
	if _, err := c.Request(context.Background(), "plugins/notes/create", core.NewObject("text", "<b>&</b>", "n", 1.5)); err != nil {
		t.Fatal(err)
	}
	if body := fetcher.last().body; body != `{"text":"<b>&</b>","n":1.5}` {
		t.Fatalf("body %s", body)
	}
	var nilObject *core.Object
	if _, err := c.Request(context.Background(), "plugins/notes/list", nilObject); err != nil {
		t.Fatal(err)
	}
	if body := fetcher.last().body; !bytes.Equal([]byte(body), []byte(`{}`)) {
		t.Fatalf("body %s", body)
	}
}
