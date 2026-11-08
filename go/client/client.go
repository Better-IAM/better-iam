// Package client is the typed HTTP client of better-iam (port of packages/client/src/index.ts). It depends on no
// server code: every route of spec/api/routes.json is a method on the Client's group fields (client.Roles.Create,
// client.Auth.SignIn, ...) with the request and answer types of go/apitypes, and Do calls any route through its typed
// operation descriptor (apitypes.OpRolesCreate). Request is the escape hatch for plugin routes.
//
//	c, err := client.New(client.Options{BaseURL: "https://app.example.com"})
//	org, err := c.Tenants.Lookup(ctx, apitypes.TenantsLookupInput{Slug: &slug})
//	session, err := c.Auth.SignIn(ctx, input)
//	decision, err := c.Authorize(ctx, apitypes.AuthorizeInput{TenantID: tenantID, Action: "documents:read", ...})
//	summary, err := c.Request(ctx, "plugins/reporting/summary", core.NewObject("tenantId", tenantID))
//
// Requests are POST {baseURL}{basePath}/{group}/{method} with the input as the JSON body, Content-Type:
// application/json and X-Better-IAM: 1 (the server's CSRF boundary requires both). Answers are { "data": ... };
// refusals are { "error": { code, message } }, returned as *IamClientError without exposing raw response bodies.
//
// The client never stores tokens: pass Token or TokenFunc for bearer authentication, or an HTTPClient with a cookie
// jar for cookie sessions. The server still authenticates and authorizes every call.
package client

//go:generate go run ./internal/gen

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// IamClientError is an HTTP or configuration error. It keeps the server's stable code and message without exposing
// raw response bodies. Configuration and input errors raised before any request have Status 0.
type IamClientError struct {
	Code    string
	Message string
	Status  int
	// RetryAfterMs is set for RATE_LIMITED answers: how long to wait before retrying, from the error's retryAfterMs or
	// the server's Retry-After header.
	RetryAfterMs *float64
	// RequestID is the X-Request-Id the request carried (see Options.RequestID), for support tickets and log lookups.
	RequestID string
	// Region is set for WRONG_REGION: the region whose deployment serves the organization.
	Region string
	// Location is set for WRONG_REGION: the organization's sign-in URL in that region, so a sign-in page can send the
	// person there.
	Location string
}

// ClientError is IamClientError under its short name.
type ClientError = IamClientError

func (e *IamClientError) Error() string { return e.Message }

func newError(code, message string, status int) *IamClientError {
	return &IamClientError{Code: code, Message: message, Status: status}
}

// Options configure a Client.
type Options struct {
	// BaseURL is the application's origin, such as "https://app.example.com". It is required (there is no current page
	// origin outside a browser).
	BaseURL string
	// BasePath is where the IAM routes are mounted; "/api/iam" when empty.
	BasePath string
	// Token is a bearer token sent on every request; empty sends none. Opaque tokens and IAM-signed session JWTs (from
	// roles.assume or sts.getSessionToken with format "jwt") are both accepted; any other shape fails with
	// INVALID_TOKEN before a request is made.
	Token string
	// TokenFunc reads the current bearer token at each request (it takes precedence over Token); ok false sends none.
	// The token is never stored by the client.
	TokenFunc func(ctx context.Context) (token string, ok bool, err error)
	// Headers are sent on every request.
	Headers http.Header
	// HeadersFunc computes the headers of each request (it takes precedence over Headers), for example a device
	// proof from DeviceProver.Headers.
	HeadersFunc func(ctx context.Context) (http.Header, error)
	// Fetch sends the request (the Fetch implementation). It takes precedence over HTTPClient.
	Fetch func(request *http.Request) (*http.Response, error)
	// HTTPClient sends the request when Fetch is nil; http.DefaultClient when both are nil. Its cookie jar, if any,
	// carries cookie sessions (Fetch's credentials: 'include'). Redirects are always refused.
	HTTPClient *http.Client
	// OnUnauthenticated is called once per request that the server refused because the presented session can no
	// longer be used, after the error is built, so an application can send the person to its login page in one place.
	// Exactly these codes trigger it: UNAUTHENTICATED (the session lapsed, was revoked, or the token is gone) and
	// SESSION_NETWORK_MISMATCH (a session bound to its network presented from another one). Credential failures such
	// as INVALID_CREDENTIALS never trigger it, and neither do codes the server also raises for sign-in or step-up
	// (MFA_REQUIRED, EMAIL_UNVERIFIED, IP_BLOCKED, ...). A hook that panics never changes what the caller sees.
	OnUnauthenticated func(err *IamClientError)
	// RetryRateLimited retries a RATE_LIMITED answer once after the server's retryAfterMs, when that wait is at most
	// RetryMaxWaitMs; longer waits surface the error unchanged. Off by default. Cancelling the call's context during
	// the wait returns at once with the context's cause, without a second request.
	RetryRateLimited bool
	// RetryMaxWaitMs caps the retry wait, in milliseconds: 5000 when zero; a negative value turns retries off.
	RetryMaxWaitMs float64
	// RequestID supplies the X-Request-Id of each request (the server echoes it and records it on its http spans); it
	// is exposed as IamClientError.RequestID. It must be 1 to 128 characters of [A-Za-z0-9._:-].
	RequestID func() string
	// GenerateRequestID sends a random X-Request-Id on every request when RequestID is nil.
	GenerateRequestID bool
}

// CallOptions are per-call options. Cancellation is the call's context.
type CallOptions struct {
	// Headers override the configured headers for this call (Content-Type and X-Better-IAM stay invariant).
	Headers http.Header
}

// MfaChallenge names a restricted sign-in challenge: auth.beginMfa and auth.confirmMfa take it instead of the
// session during MFA enrollment after sign-in.
type MfaChallenge struct {
	TenantID  string `json:"tenantId"`
	Challenge string `json:"challenge"`
}

// ConfirmMfaInput is the client form of auth.confirmMfa: Credential is the restricted challenge during enrollment
// after sign-in, nil during an authenticated session.
type ConfirmMfaInput struct {
	Credential     *MfaChallenge `json:"credential,omitzero"`
	Code           string        `json:"code"`
	RememberDevice *bool         `json:"rememberDevice,omitzero"`
}

// Client is the typed IAM client. Its group fields (generated in client_gen.go) have one method per route.
type Client struct {
	groups

	origin      string
	basePath    string
	options     Options
	send        func(request *http.Request) (*http.Response, error)
	retryWaitMs float64
}

// noInputAuthMethods are auth methods whose only server parameter is the credential: the client sends {}.
var noInputAuthMethods = map[string]bool{
	"signOut": true, "getSession": true, "listSessions": true, "revokeOtherSessions": true,
	"beginPasskeyRegistration": true, "listPasskeys": true, "regenerateRecoveryCodes": true, "disableMfa": true,
	"listTrustedDevices": true, "revokeTrustedDevices": true, "mfaStatus": true,
}

// noInputMethods are methods outside auth whose only server parameter is the credential.
var noInputMethods = map[string]bool{"sts/getCallerIdentity": true, "links/list": true, "clearances/templates": true}

// sessionEndingCodes are refusals that end the presented session wherever it is used next, so OnUnauthenticated
// fires for them. Codes the server also raises from sign-in or step-up flows stay out: the client cannot tell those
// apart from a dead session, and a login redirect mid-step-up would lose work.
var sessionEndingCodes = map[string]bool{"UNAUTHENTICATED": true, "SESSION_NETWORK_MISMATCH": true}

var reserved = map[string]bool{
	"then": true, "catch": true, "finally": true, "toJSON": true, "constructor": true, "prototype": true, "__proto__": true,
}

var (
	segmentPattern   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)
	opaquePattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{16,512}$`)
	basePathPattern  = regexp.MustCompile(`^/[A-Za-z0-9_/-]+$`)
	requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	locationPattern  = regexp.MustCompile(`^https?://`)
)

func routeSegment(value string) bool {
	return segmentPattern.MatchString(value) && !reserved[value]
}

// bearerToken accepts the bearer shapes the server can accept: an opaque token (sessions, API keys, role sessions
// and session tokens, prefixed biam_... or legacy) or an IAM-signed session JWT (three base64url segments, at most
// 4096 characters). Anything else never leaves the client, so a stray value cannot end up in an Authorization header.
func bearerToken(value string) bool {
	if opaquePattern.MatchString(value) {
		return true
	}
	if len(value) > 4096 {
		return false
	}
	// Three base64url segments of 2-1024, 2-3072 and 2-1024 characters (Go's regexp caps repeat counts at 1000).
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for index, limit := range []int{1024, 3072, 1024} {
		part := parts[index]
		if len(part) < 2 || len(part) > limit {
			return false
		}
		for i := 0; i < len(part); i++ {
			c := part[i]
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}

// New creates a client (createIamClient). It fails with INVALID_CONFIG (status 0) for a missing or unusable BaseURL
// or BasePath.
func New(options Options) (*Client, error) {
	if options.BaseURL == "" {
		return nil, newError("INVALID_CONFIG", "baseURL is required outside a browser", 0)
	}
	base, err := url.Parse(options.BaseURL)
	if err != nil || base.Scheme == "" || base.Opaque != "" || base.Host == "" || base.Hostname() == "" {
		return nil, newError("INVALID_CONFIG", "baseURL must be an absolute HTTP(S) URL", 0)
	}
	username, password := "", ""
	if base.User != nil {
		username = base.User.Username()
		password, _ = base.User.Password()
	}
	if (base.Scheme != "http" && base.Scheme != "https") || username != "" || password != "" || base.RawQuery != "" || base.Fragment != "" {
		return nil, newError("INVALID_CONFIG", "baseURL must be an HTTP(S) URL without credentials, query, or fragment", 0)
	}
	basePath := options.BasePath
	if basePath == "" {
		basePath = apitypes.DefaultBasePath
	}
	if !basePathPattern.MatchString(basePath) || strings.HasSuffix(basePath, "/") {
		return nil, newError("INVALID_CONFIG", "basePath must be an absolute path without a trailing slash", 0)
	}
	c := &Client{origin: origin(base), basePath: basePath, options: options}
	switch {
	case options.Fetch != nil:
		c.send = options.Fetch
	default:
		httpClient := options.HTTPClient
		if httpClient == nil {
			httpClient = http.DefaultClient
		}
		// redirect: 'error': a redirected IAM call fails instead of following the redirect.
		refusing := *httpClient
		refusing.CheckRedirect = func(*http.Request, []*http.Request) error {
			return errors.New("the IAM server answered with a redirect")
		}
		c.send = refusing.Do
	}
	if options.RetryRateLimited {
		c.retryWaitMs = options.RetryMaxWaitMs
		if c.retryWaitMs == 0 {
			c.retryWaitMs = 5_000
		}
	}
	c.groups = newGroups(c)
	return c, nil
}

// origin is the URL's serialized origin: scheme://host[:port], with the host lowercased and the scheme's default
// port dropped (WHATWG URL origin).
func origin(base *url.URL) string {
	host := strings.ToLower(base.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := base.Port()
	if (base.Scheme == "http" && port == "80") || (base.Scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	return base.Scheme + "://" + host
}

// String is the client's tag (Symbol.toStringTag of the TypeScript client).
func (c *Client) String() string { return "BetterIamClient" }

// BaseURL is the origin the client sends requests to.
func (c *Client) BaseURL() string { return c.origin }

// BasePath is where the client expects the IAM routes.
func (c *Client) BasePath() string { return c.basePath }

// Request posts input to a route below the basePath ($request), such as "plugins/projects/list", and returns the
// answer's data as a model value (*core.Object, []any, string, float64, bool or nil). Every path segment must be a
// plain identifier; anything else fails with INVALID_PATH before a request is made.
func (c *Client) Request(ctx context.Context, path string, input any, options ...CallOptions) (any, error) {
	return Call[any](ctx, c, path, input, options...)
}

// Call posts input to a route below the basePath and decodes the answer's data into Out.
func Call[Out any](ctx context.Context, c *Client, path string, input any, options ...CallOptions) (Out, error) {
	var out Out
	data, err := c.request(ctx, path, input, options)
	if err != nil {
		return out, err
	}
	if err := decodeData(data, &out); err != nil {
		return out, err
	}
	return out, nil
}

// Do calls the route of a typed operation descriptor (apitypes.OpRolesCreate, ...) with its request type and decodes
// the answer into its answer type.
func Do[In, Out any](ctx context.Context, c *Client, op apitypes.Op[In, Out], input In, options ...CallOptions) (Out, error) {
	return Call[Out](ctx, c, op.Path, input, options...)
}

// Authorize asks whether the caller may perform an action on a resource (POST {basePath}/authorize).
func (c *Client) Authorize(ctx context.Context, input apitypes.AuthorizeInput, options ...CallOptions) (apitypes.AuthorizeOutput, error) {
	return Do(ctx, c, apitypes.OpAuthorize, input, options...)
}

// AuthorizeMany answers several authorization checks at once (POST {basePath}/authorizeMany).
func (c *Client) AuthorizeMany(ctx context.Context, input apitypes.AuthorizeManyInput, options ...CallOptions) (apitypes.AuthorizeManyOutput, error) {
	return Do(ctx, c, apitypes.OpAuthorizeMany, input, options...)
}

// ListAccessible lists the resources of a type the caller may act on (POST {basePath}/listAccessible).
func (c *Client) ListAccessible(ctx context.Context, input apitypes.ListAccessibleInput, options ...CallOptions) (apitypes.ListAccessibleOutput, error) {
	return Do(ctx, c, apitypes.OpListAccessible, input, options...)
}

// callNoInput posts {} to a credential-only route.
func callNoInput[Out any](ctx context.Context, c *Client, path string, options []CallOptions) (Out, error) {
	return Call[Out](ctx, c, path, core.NewObject(), options...)
}

func (c *Client) request(ctx context.Context, path string, input any, options []CallOptions) (any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	data, err := c.attempt(ctx, path, input, options)
	if err == nil {
		return data, nil
	}
	var refused *IamClientError
	if errors.As(err, &refused) && refused.Code == "RATE_LIMITED" && c.retryWaitMs > 0 && refused.RetryAfterMs != nil &&
		*refused.RetryAfterMs <= c.retryWaitMs {
		if err := wait(ctx, *refused.RetryAfterMs); err != nil {
			return nil, err
		}
		return c.attempt(ctx, path, input, options)
	}
	return nil, err
}

// wait is the retry wait (tests replace it to control time).
var wait = sleep

// sleep waits ms milliseconds, returning the context's cause at once when the context ends first (or has already
// ended), so an aborted call never sends a doomed second request.
func sleep(ctx context.Context, ms float64) error {
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	timer := time.NewTimer(time.Duration(ms * float64(time.Millisecond)))
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func (c *Client) nextRequestID() (string, bool) {
	if c.options.RequestID != nil {
		return c.options.RequestID(), true
	}
	if c.options.GenerateRequestID {
		return randomUUID(), true
	}
	return "", false
}

func (c *Client) attempt(ctx context.Context, path string, input any, options []CallOptions) (any, error) {
	if path == "" {
		return nil, newError("INVALID_PATH", "IAM routes must use plain relative path segments", 0)
	}
	for _, segment := range strings.Split(path, "/") {
		if !routeSegment(segment) {
			return nil, newError("INVALID_PATH", "IAM routes must use plain relative path segments", 0)
		}
	}
	configured := c.options.Headers
	if c.options.HeadersFunc != nil {
		computed, err := c.options.HeadersFunc(ctx)
		if err != nil {
			return nil, err
		}
		configured = computed
	}
	headers := http.Header{}
	for key, values := range configured {
		headers[http.CanonicalHeaderKey(key)] = append([]string(nil), values...)
	}
	for _, option := range options {
		for key, values := range option.Headers {
			headers[http.CanonicalHeaderKey(key)] = append([]string(nil), values...)
		}
	}
	// These headers are invariant: the server's CSRF boundary requires both.
	headers.Set("Content-Type", "application/json")
	headers.Set("X-Better-Iam", "1")
	requestID, hasRequestID := c.nextRequestID()
	if hasRequestID {
		if !requestIDPattern.MatchString(requestID) {
			return nil, newError("INVALID_CONFIG", "requestId must be a short plain token", 0)
		}
		headers.Set("X-Request-Id", requestID)
	}
	fail := func(code, message string, status int, retryAfterMs *float64) *IamClientError {
		failure := &IamClientError{Code: code, Message: message, Status: status, RetryAfterMs: retryAfterMs, RequestID: requestID}
		if sessionEndingCodes[code] && c.options.OnUnauthenticated != nil {
			func() {
				// A hook that panics never changes what the caller sees.
				defer func() { _ = recover() }()
				c.options.OnUnauthenticated(failure)
			}()
		}
		return failure
	}
	token, hasToken := c.options.Token, c.options.Token != ""
	if c.options.TokenFunc != nil {
		read, ok, err := c.options.TokenFunc(ctx)
		if err != nil {
			return nil, err
		}
		token, hasToken = read, ok
	}
	if hasToken {
		if !bearerToken(token) {
			return nil, newError("INVALID_TOKEN", "Invalid bearer token format", 0)
		}
		headers.Set("Authorization", "Bearer "+token)
	}
	body, err := encodeBody(input)
	if err != nil {
		return nil, newError("INVALID_INPUT", "Request input must be serializable JSON", 0)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+c.basePath+"/"+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header = headers
	response, err := c.send(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}
		return nil, err
	}
	raw, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		if ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}
		return nil, fail("INVALID_RESPONSE", "The IAM server returned an invalid response", response.StatusCode, nil)
	}
	parsed, err := core.ParseJSON(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")))
	if err != nil {
		return nil, fail("INVALID_RESPONSE", "The IAM server returned an invalid response", response.StatusCode, nil)
	}
	envelope, ok := parsed.(*core.Object)
	if !ok || envelope == nil {
		return nil, fail("INVALID_RESPONSE", "The IAM server returned an invalid response", response.StatusCode, nil)
	}
	if envelope.Has("error") {
		refusal, _ := envelope.Get("error").(*core.Object)
		if refusal != nil {
			code, codeOK := refusal.Get("code").(string)
			message, messageOK := refusal.Get("message").(string)
			if codeOK && messageOK {
				var retryAfterMs *float64
				if fromBody, ok := refusal.Get("retryAfterMs").(float64); ok {
					retryAfterMs = &fromBody
				} else if header := jsNumber(response.Header.Get("Retry-After"), response.Header.Values("Retry-After") != nil); !math.IsNaN(header) && !math.IsInf(header, 0) && header > 0 {
					fromHeader := header * 1000
					retryAfterMs = &fromHeader
				}
				failure := fail(code, message, response.StatusCode, retryAfterMs)
				if region, ok := refusal.Get("region").(string); ok {
					failure.Region = region
				}
				if location, ok := refusal.Get("location").(string); ok && locationPattern.MatchString(location) {
					failure.Location = location
				}
				return nil, failure
			}
		}
		return nil, fail("INVALID_RESPONSE", "The IAM server returned an invalid error response", response.StatusCode, nil)
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, fail("HTTP_ERROR", "The IAM server rejected the request", response.StatusCode, nil)
	}
	if !envelope.Has("data") {
		return nil, fail("INVALID_RESPONSE", "The IAM server returned an invalid response", response.StatusCode, nil)
	}
	return envelope.Get("data"), nil
}

// encodeBody is JSON.stringify(input ?? {}): nil (and a nil object) becomes {}. HTML characters are not escaped, as
// in JavaScript.
func encodeBody(input any) ([]byte, error) {
	if input == nil || core.IsUndefined(input) {
		return []byte("{}"), nil
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(input); err != nil {
		return nil, err
	}
	body := bytes.TrimRight(buffer.Bytes(), "\n")
	if string(body) == "null" {
		return []byte("{}"), nil
	}
	return body, nil
}

// decodeData converts the answer's data (a model value) into out.
func decodeData(data any, out any) error {
	switch target := out.(type) {
	case *any:
		*target = data
		return nil
	case **core.Object:
		if data == nil {
			*target = nil
			return nil
		}
		if object, ok := data.(*core.Object); ok {
			*target = object
			return nil
		}
	}
	text, _, err := core.Stringify(data)
	if err != nil {
		return newError("INVALID_RESPONSE", "The IAM server returned an invalid response", 0)
	}
	if err := json.Unmarshal([]byte(text), out); err != nil {
		return &IamClientError{Code: "INVALID_RESPONSE", Message: "The IAM server returned an unexpected answer: " + err.Error()}
	}
	return nil
}

// jsNumber is JavaScript's Number(text) for a header value; Number(null) (no header) is 0.
func jsNumber(text string, present bool) float64 {
	if !present {
		return 0
	}
	trimmed := core.JSTrim(text)
	if trimmed == "" {
		return 0
	}
	if len(trimmed) > 2 && trimmed[0] == '0' {
		base := 0
		switch trimmed[1] {
		case 'x', 'X':
			base = 16
		case 'o', 'O':
			base = 8
		case 'b', 'B':
			base = 2
		}
		if base != 0 {
			value, err := strconv.ParseUint(trimmed[2:], base, 64)
			if err != nil {
				return math.NaN()
			}
			return float64(value)
		}
	}
	switch trimmed {
	case "Infinity", "+Infinity":
		return math.Inf(1)
	case "-Infinity":
		return math.Inf(-1)
	}
	for _, r := range trimmed {
		if !(r >= '0' && r <= '9') && r != '.' && r != 'e' && r != 'E' && r != '+' && r != '-' {
			return math.NaN()
		}
	}
	value, err := strconv.ParseFloat(trimmed, 64)
	if err != nil {
		var numError *strconv.NumError
		if errors.As(err, &numError) && errors.Is(numError.Err, strconv.ErrRange) {
			return value
		}
		return math.NaN()
	}
	return value
}

// randomUUID is crypto.randomUUID(): a random (version 4) UUID in lowercase.
func randomUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
