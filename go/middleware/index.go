// Package middleware is the Go port of @better-iam/middleware (packages/middleware/src/index.ts): the per-request
// helpers every framework integration exposes (sessions, step-up, decisions, the in-process client, sign-out), the
// CSRF Origin check for application routes, guards, and the refusal answers (the IAM JSON error envelope, or a
// redirect to the login / step-up page for page navigations).
//
// The net/http integration (the counterpart of the Express and Fastify adapters) is in nethttp.go; chi, gin and echo
// integrations live in the subpackages of the same names.
package middleware

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

// IAM is the server surface the middleware uses (IamLike). Server(iam) adapts a *server.BetterIam; the optional
// members of IamLike are the optional interfaces below (NodeHandler, AccessibleLister, ResourcePlanner,
// AssertionIssuer, EndpointProvider, HostResolver).
type IAM interface {
	// GetSession is api.auth.getSession: the credential's identity and session.
	GetSession(ctx context.Context, credential core.CredentialInput) (*core.Object, error)
	// Handle is the fetch-style handler (`handler`).
	Handle(r *http.Request) *server.Response
	// Require refuses unless the request is allowed (`require`).
	Require(ctx context.Context, request server.AuthorizationRequest) error
	// AuthorizeMany evaluates up to 50 checks for one tenant (`authorizeMany`): `{ results: [...] }`.
	AuthorizeMany(ctx context.Context, request server.BatchAuthorizationRequest) (*core.Object, error)
}

// NodeHandler is the Node transport (`nodeHandler`): it serves node-only protocol mounts (the OAuth provider) too.
type NodeHandler interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}

// AccessibleLister is `listAccessible`.
type AccessibleLister interface {
	ListAccessible(ctx context.Context, request server.AccessibleResourcesRequest) (*core.Object, error)
}

// ResourcePlanner is query planning (`planResources`): which resources of a type the caller may act on, as a filter.
type ResourcePlanner interface {
	PlanResources(ctx context.Context, request server.PlanResourcesRequest) (*core.Object, error)
}

// AssertionIssuer is api.assertions.issue.
type AssertionIssuer interface {
	IssueAssertion(ctx context.Context, credential core.CredentialInput, input *core.Object) (*core.Object, error)
}

// EndpointProvider is `endpoint`: where the IAM HTTP API is served.
type EndpointProvider interface {
	IamEndpoint() server.Endpoint
}

// HostResolver is `hosts` (organization sign-in addresses): when present, in-process calls keep the visitor's host so
// they are pinned to that organization.
type HostResolver interface {
	ResolveHost(ctx context.Context, host string) (*server.HostMatch, error)
}

// ResourceRef is a resource the policy engine decides on (`{ type, id }`).
type ResourceRef = server.ResourceTarget

// AuthorizeCheck is one advisory check.
type AuthorizeCheck struct {
	Action   string
	Resource ResourceRef
}

// AuthorizeResult is one advisory decision.
type AuthorizeResult struct {
	Action   string
	Resource ResourceRef
	Allowed  bool
	Reason   string
}

// AssertionInput is the input of a signed assertion about the caller for a downstream service.
type AssertionInput struct {
	TenantID   string
	Audience   string
	TTLSeconds *float64
	Claims     *core.Object
}

// MfaRequirement is StepUpRequirement.mfa: MfaOff (false), MfaRequired (true) or MfaFresh ('fresh').
type MfaRequirement string

const (
	// MfaOff asks for nothing (`mfa: false`, or no `mfa`).
	MfaOff MfaRequirement = ""
	// MfaRequired needs a session that completed MFA (`mfa: true`).
	MfaRequired MfaRequirement = "required"
	// MfaFresh also refuses remembered devices, impersonation, assumed roles, and API keys (`mfa: 'fresh'`).
	MfaFresh MfaRequirement = "fresh"
)

// StepUpRequirement is extra assurance a session must show. MaxAgeMs needs a recent sign-in.
type StepUpRequirement struct {
	MFA      MfaRequirement
	MaxAgeMs *float64
}

// StepUpFailure is why a session does not meet a step-up requirement.
type StepUpFailure struct {
	// Code is MFA_REQUIRED, RECENT_AUTH_REQUIRED or IMPERSONATION_RESTRICTED.
	Code string
	// Reason is mfa, recent or impersonation.
	Reason  string
	Message string
	Status  int
}

// IamRequestError is a refusal raised by the request helpers and guards, with the IAM Code and HTTP Status. Reason is
// set for step-up failures (mfa, recent, impersonation). Framework integrations turn it into the IAM JSON error
// envelope or, for page navigations, a redirect to the login / step-up page.
type IamRequestError struct {
	Code    string
	Message string
	Status  int
	Reason  string
}

func (e *IamRequestError) Error() string { return e.Message }

// Name is the JavaScript error name ("IamRequestError").
func (e *IamRequestError) Name() string { return "IamRequestError" }

// NewIamRequestError builds an IamRequestError.
func NewIamRequestError(code, message string, status int, reason ...string) *IamRequestError {
	err := &IamRequestError{Code: code, Message: message, Status: status}
	if len(reason) > 0 {
		err.Reason = reason[0]
	}
	return err
}

// TypeError is a misuse of the helpers (a JavaScript TypeError).
type TypeError struct{ Message string }

func (e *TypeError) Error() string { return e.Message }

var authenticationCodes = map[string]bool{
	"UNAUTHENTICATED":    true,
	"MFA_REQUIRED":       true,
	"EMAIL_UNVERIFIED":   true,
	"TENANT_INACTIVE":    true,
	"TENANT_UNAVAILABLE": true,
}

// Refusal is an error carrying an IAM code and an HTTP status (server IamError, client errors, IamRequestError).
type Refusal struct {
	Code    string
	Message string
	Status  int
	// Reason is the step-up reason of an IamRequestError ("" otherwise).
	Reason string
}

// RefusalOf is the refusal err carries (isIamRefusal): a *core.IamError, a *ClientError or an *IamRequestError.
func RefusalOf(err error) (Refusal, bool) {
	if err == nil {
		return Refusal{}, false
	}
	var request *IamRequestError
	if errors.As(err, &request) {
		return Refusal{Code: request.Code, Message: request.Message, Status: request.Status, Reason: request.Reason}, true
	}
	var known *core.IamError
	if errors.As(err, &known) {
		return Refusal{Code: known.Code, Message: known.Message, Status: known.Status}, true
	}
	var client *ClientError
	if errors.As(err, &client) {
		return Refusal{Code: client.Code, Message: client.Message, Status: client.Status}, true
	}
	return Refusal{}, false
}

// ErrorCode is the IAM code an error carries ("", false when it has none).
func ErrorCode(err error) (string, bool) {
	refusal, ok := RefusalOf(err)
	return refusal.Code, ok
}

// ErrorStatus is the HTTP status an error carries (0, false when it has none).
func ErrorStatus(err error) (int, bool) {
	refusal, ok := RefusalOf(err)
	return refusal.Status, ok
}

// IsAuthenticationError is true for the errors getSession raises when there is no usable session.
func IsAuthenticationError(err error) bool {
	code, ok := ErrorCode(err)
	return ok && authenticationCodes[code]
}

// IsIamRefusal is true for any error carrying an IAM code and an HTTP status.
func IsIamRefusal(err error) bool {
	_, ok := RefusalOf(err)
	return ok
}

var unsafeRedirect = regexp.MustCompile(`[\\\x00-\x1f]`)

// SafeRedirectPath is a same-site relative path safe to redirect to, or fallback ("/" when none is given). It
// refuses schemes, `//host`, and backslash tricks.
func SafeRedirectPath(value string, fallback ...string) string {
	otherwise := "/"
	if len(fallback) > 0 {
		otherwise = fallback[0]
	}
	if value == "" || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || unsafeRedirect.MatchString(value) {
		return otherwise
	}
	// new URL(value, 'http://better-iam.invalid'): a path-absolute reference keeps the base's origin.
	path := relativeReference(value)
	if strings.HasPrefix(path, "//") {
		return otherwise
	}
	return path
}

// relativeReference is `${url.pathname}${url.search}${url.hash}` of a path-absolute reference resolved against an
// http URL, as the URL standard parses it: dot segments removed (also percent-encoded ones) and the path, query and
// fragment percent-encode sets applied.
func relativeReference(value string) string {
	rest, fragment, hasFragment := strings.Cut(value, "#")
	path, query, hasQuery := strings.Cut(rest, "?")
	segments := strings.Split(path[1:], "/")
	out := make([]string, 0, len(segments))
	for index, segment := range segments {
		last := index == len(segments)-1
		lower := strings.ToLower(segment)
		switch lower {
		case "..", ".%2e", "%2e.", "%2e%2e":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			if last {
				out = append(out, "")
			}
		case ".", "%2e":
			if last {
				out = append(out, "")
			}
		default:
			out = append(out, percentEncode(segment, pathEncodeSet))
		}
	}
	result := "/" + strings.Join(out, "/")
	if hasQuery && query != "" {
		result += "?" + percentEncode(query, specialQueryEncodeSet)
	}
	if hasFragment && fragment != "" {
		result += "#" + percentEncode(fragment, fragmentEncodeSet)
	}
	return result
}

const (
	fragmentEncodeSet     = " \"<>`"
	pathEncodeSet         = " \"<>`#?{}"
	specialQueryEncodeSet = " \"#<>'"
)

// percentEncode applies a URL-standard percent-encode set: C0 controls, code points above U+007E, and set.
func percentEncode(value, set string) string {
	var out strings.Builder
	for index := 0; index < len(value); index++ {
		c := value[index]
		if c < 0x20 || c > 0x7e || strings.IndexByte(set, c) >= 0 {
			fmt.Fprintf(&out, "%%%02X", c)
			continue
		}
		out.WriteByte(c)
	}
	return out.String()
}

// QueryParam is one query parameter WithQuery appends.
type QueryParam struct {
	Name  string
	Value string
}

// WithQuery appends query parameters (URLSearchParams serialization).
func WithQuery(target string, params ...QueryParam) string {
	if len(params) == 0 {
		return target
	}
	parts := make([]string, len(params))
	for index, param := range params {
		parts[index] = formEncode(param.Name) + "=" + formEncode(param.Value)
	}
	separator := "?"
	if strings.Contains(target, "?") {
		separator = "&"
	}
	return target + separator + strings.Join(parts, "&")
}

// formEncode is the application/x-www-form-urlencoded byte serializer URLSearchParams uses.
func formEncode(value string) string {
	var out strings.Builder
	for index := 0; index < len(value); index++ {
		c := value[index]
		switch {
		case c == ' ':
			out.WriteByte('+')
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '*', c == '-', c == '.', c == '_':
			out.WriteByte(c)
		default:
			fmt.Fprintf(&out, "%%%02X", c)
		}
	}
	return out.String()
}

// UnderPath is true when pathname is prefix or below it on a segment boundary.
func UnderPath(pathname, prefix string) bool {
	base := prefix
	if strings.HasSuffix(prefix, "/") && prefix != "/" {
		base = prefix[:len(prefix)-1]
	}
	return base == "/" || pathname == base || strings.HasPrefix(pathname, base+"/")
}

// TenantOf is the tenant a session (a getSession result) acts in ("" when none).
func TenantOf(session *core.Object) string {
	if session == nil {
		return ""
	}
	inner, ok := session.Get("session").(*core.Object)
	if !ok {
		return ""
	}
	tenantID, _ := inner.Get("tenantId").(string)
	return tenantID
}

// CheckStepUp checks a session against a step-up requirement; nil when it qualifies. It accepts the getSession
// result or its inner session record. Impersonated sessions always fail a recency requirement, as the server's own
// check does. now is the current time in milliseconds (Date.now when omitted).
func CheckStepUp(session *core.Object, requirement StepUpRequirement, now ...int64) (*StepUpFailure, error) {
	mfa, maxAgeMs := requirement.MFA, requirement.MaxAgeMs
	if mfa != MfaOff && mfa != MfaRequired && mfa != MfaFresh {
		return nil, &TypeError{Message: "stepUp.mfa must be true, false, or 'fresh'"}
	}
	if maxAgeMs != nil && (math.IsNaN(*maxAgeMs) || math.IsInf(*maxAgeMs, 0) || *maxAgeMs <= 0) {
		return nil, &TypeError{Message: "stepUp.maxAgeMs must be a positive, finite number of milliseconds"}
	}
	current := time.Now().UnixMilli()
	if len(now) > 0 {
		current = now[0]
	}
	record := session
	if record == nil {
		record = core.NewObject()
	}
	if inner, ok := record.Get("session").(*core.Object); ok {
		record = inner
	}
	failure := func(code, reason, message string) *StepUpFailure {
		return &StepUpFailure{Code: code, Reason: reason, Message: message, Status: 403}
	}
	impersonated := truthy(record.Get("impersonatorId")) || record.Get("method") == "impersonation"
	if impersonated && (maxAgeMs != nil || mfa == MfaFresh) {
		return failure("IMPERSONATION_RESTRICTED", "impersonation", "This operation is unavailable while impersonating a member"), nil
	}
	if mfa != MfaOff && record.Get("mfa") != true {
		return failure("MFA_REQUIRED", "mfa", "Multi-factor authentication is required"), nil
	}
	if mfa == MfaFresh {
		if truthy(record.Get("trustedDeviceId")) {
			return failure("MFA_REQUIRED", "mfa", "Verify your second factor again to continue"), nil
		}
		if record.Get("kind") != "user" || truthy(record.Get("sourceSessionId")) {
			return failure("MFA_REQUIRED", "mfa", "This credential cannot show a fresh second factor; use a signed-in session"), nil
		}
	}
	if maxAgeMs != nil {
		at, ok := record.Get("authenticatedAt").(float64)
		if !ok || at > float64(current) || !(float64(current)-at <= *maxAgeMs) {
			return failure("RECENT_AUTH_REQUIRED", "recent", "Reauthenticate to perform this operation"), nil
		}
	}
	return nil, nil
}

// truthy is JavaScript truthiness.
func truthy(value any) bool {
	switch v := value.(type) {
	case nil, core.UndefinedType:
		return false
	case bool:
		return v
	case float64:
		return v != 0 && !math.IsNaN(v)
	case string:
		return v != ""
	}
	return true
}

// Cookies is an insertion-ordered set of cookie name/value pairs (a JavaScript Map).
type Cookies struct {
	names  []string
	values map[string]string
}

func newCookies() *Cookies { return &Cookies{values: map[string]string{}} }

// Get is the value of a cookie.
func (c *Cookies) Get(name string) (string, bool) {
	value, ok := c.values[name]
	return value, ok
}

// Has is whether the cookie is present.
func (c *Cookies) Has(name string) bool {
	_, ok := c.values[name]
	return ok
}

// Set sets a cookie, keeping its position when it is already present.
func (c *Cookies) Set(name, value string) {
	if _, ok := c.values[name]; !ok {
		c.names = append(c.names, name)
	}
	c.values[name] = value
}

// Delete removes a cookie.
func (c *Cookies) Delete(name string) {
	if _, ok := c.values[name]; !ok {
		return
	}
	delete(c.values, name)
	for index, existing := range c.names {
		if existing == name {
			c.names = append(c.names[:index:index], c.names[index+1:]...)
			break
		}
	}
}

// Len is the number of cookies.
func (c *Cookies) Len() int { return len(c.names) }

// Entries is the name/value pairs in order.
func (c *Cookies) Entries() [][2]string {
	entries := make([][2]string, len(c.names))
	for index, name := range c.names {
		entries[index] = [2]string{name, c.values[name]}
	}
	return entries
}

// ParseCookieHeader splits a Cookie header into name/value pairs (values left encoded; the first of a repeated name
// wins).
func ParseCookieHeader(header string) *Cookies {
	cookies := newCookies()
	for _, part := range strings.Split(header, ";") {
		separator := strings.Index(part, "=")
		if separator <= 0 {
			continue
		}
		name := core.JSTrim(part[:separator])
		if name != "" && !cookies.Has(name) {
			cookies.Set(name, core.JSTrim(part[separator+1:]))
		}
	}
	return cookies
}

// SetCookie is the name, raw value, and whether a Set-Cookie header deletes the cookie.
type SetCookie struct {
	Name    string
	Value   string
	Deleted bool
}

var maxAgeValue = regexp.MustCompile(`^-?\d+$`)

// SetCookieSummary is the name, raw value, and whether a Set-Cookie header deletes the cookie (`Max-Age=0` or a past
// `Expires`); nil for a header without a name. now is in milliseconds (Date.now when omitted).
func SetCookieSummary(header string, now ...int64) *SetCookie {
	current := time.Now().UnixMilli()
	if len(now) > 0 {
		current = now[0]
	}
	parts := strings.Split(header, ";")
	pair, attributes := parts[0], parts[1:]
	separator := strings.Index(pair, "=")
	if pair == "" || separator <= 0 {
		return nil
	}
	deleted := false
	for _, attribute := range attributes {
		pieces := strings.Split(attribute, "=")
		setting := core.JSTrim(strings.Join(pieces[1:], "="))
		name := strings.ToLower(core.JSTrim(pieces[0]))
		if name == "max-age" && maxAgeValue.MatchString(setting) {
			if value, err := strconv.ParseFloat(setting, 64); err == nil && value <= 0 {
				deleted = true
			}
		}
		if name == "expires" {
			if at, ok := parseDate(setting); ok && at <= current {
				deleted = true
			}
		}
	}
	return &SetCookie{Name: core.JSTrim(pair[:separator]), Value: core.JSTrim(pair[separator+1:]), Deleted: deleted}
}

// parseDate is Date.parse for the date formats cookies use (HTTP dates and ISO strings).
func parseDate(value string) (int64, bool) {
	if at, err := http.ParseTime(value); err == nil {
		return at.UnixMilli(), true
	}
	for _, layout := range []string{
		"Mon, 02-Jan-2006 15:04:05 MST", "Mon, 02 Jan 2006 15:04:05 -0700", time.RFC3339Nano, "2006-01-02T15:04:05",
		"2006-01-02", time.RFC1123,
	} {
		if at, err := time.Parse(layout, value); err == nil {
			return at.UnixMilli(), true
		}
	}
	return 0, false
}

// RequestBinding is what a framework integration provides for one request.
type RequestBinding struct {
	// URL is the incoming request's URL (the in-process client's origin when the instance has no endpoint).
	URL *url.URL
	// Header is the incoming request's headers.
	Header http.Header
	// SetCookie appends one Set-Cookie header to the outgoing response.
	SetCookie func(header string)
}

// forwardedHeaders are the request headers forwarded when the in-process client calls the IAM handler.
var forwardedHeaders = []string{
	"authorization", "user-agent", "accept-language", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
	"x-real-ip", "x-request-id",
	// A registered device's signed proof (verified by the server against the enrolled key and the session).
	"x-better-iam-device",
}

var sessionCookies = []string{"better-iam.session", "__Host-better-iam.session"}

// HelperOptions are the request helpers' options.
type HelperOptions struct {
	// BasePath is where the IAM HTTP API is served; defaults to the instance's endpoint.basePath, else /api/iam.
	BasePath string
	// Now is the clock in milliseconds (Date.now when nil).
	Now func() int64
}

// future is a settled-once value several goroutines wait for (a shared Promise).
type future[T any] struct {
	done  chan struct{}
	value T
	err   error
}

func newFuture[T any]() *future[T] { return &future[T]{done: make(chan struct{})} }

func (f *future[T]) settle(value T, err error) {
	f.value, f.err = value, err
	close(f.done)
}

func (f *future[T]) wait(ctx context.Context) (T, error) {
	select {
	case <-f.done:
		return f.value, f.err
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}

type queuedCheck struct {
	ctx      context.Context
	tenantID string
	check    AuthorizeCheck
	answer   *future[bool]
}

// scheduleFlush runs a batch of advisory checks after the calls made together have queued (setTimeout(flush, 0)).
var scheduleFlush = func(flush func()) { time.AfterFunc(0, flush) }

// Helpers are the per-request helpers every framework integration exposes (IamRequest). Sessions and decisions are
// memoized for the request, and cookies the in-process client receives count for later calls. They are safe for
// concurrent use by the goroutines of one request.
type Helpers struct {
	resolve func(ctx context.Context) (IAM, error)
	binding RequestBinding
	options HelperOptions
	clock   func() int64

	mu sync.Mutex
	// overrides are cookies set (nil value: deleted) during this request; they override the incoming header.
	overrides     []string
	overrideValue map[string]*string
	session       *future[*core.Object]
	queue         []*queuedCheck
	answers       map[string]*future[bool]
	client        *Client
}

// NewHelpers builds the per-request helpers over a framework's request and response (createRequestHelpers).
// Framework integrations call this once per request.
func NewHelpers(resolve func(ctx context.Context) (IAM, error), binding RequestBinding, options HelperOptions) *Helpers {
	clock := options.Now
	if clock == nil {
		clock = func() int64 { return time.Now().UnixMilli() }
	}
	if binding.Header == nil {
		binding.Header = http.Header{}
	}
	if binding.SetCookie == nil {
		binding.SetCookie = func(string) {}
	}
	return &Helpers{
		resolve: resolve, binding: binding, options: options, clock: clock,
		overrideValue: map[string]*string{}, answers: map[string]*future[bool]{},
	}
}

func (h *Helpers) forget() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.session = nil
	h.answers = map[string]*future[bool]{}
}

// headerGet is Headers#get: the values of a header joined (cookies with "; ", others with ", "), and whether present.
func headerGet(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) == 0 {
		return "", false
	}
	separator := ", "
	if strings.EqualFold(name, "cookie") {
		separator = "; "
	}
	return strings.Join(values, separator), true
}

// Header is this request's headers with the cookies set during the request.
func (h *Helpers) Header() http.Header {
	merged := h.binding.Header.Clone()
	if merged == nil {
		merged = http.Header{}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.overrides) == 0 {
		return merged
	}
	incoming, _ := headerGet(h.binding.Header, "cookie")
	jar := ParseCookieHeader(incoming)
	for _, name := range h.overrides {
		if value := h.overrideValue[name]; value == nil {
			jar.Delete(name)
		} else {
			jar.Set(name, *value)
		}
	}
	pairs := make([]string, 0, jar.Len())
	for _, entry := range jar.Entries() {
		pairs = append(pairs, entry[0]+"="+entry[1])
	}
	if cookie := strings.Join(pairs, "; "); cookie != "" {
		merged.Set("Cookie", cookie)
	} else {
		merged.Del("Cookie")
	}
	return merged
}

// Credential is the credential for direct iam.API calls: this request's headers with cookies set during the request.
func (h *Helpers) Credential() core.CredentialInput {
	return core.CredentialInput{Headers: h.Header()}
}

func (h *Helpers) setCookie(header string) {
	h.binding.SetCookie(header)
	summary := SetCookieSummary(header, h.clock())
	if summary == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.overrideValue[summary.Name]; !ok {
		h.overrides = append(h.overrides, summary.Name)
	}
	if summary.Deleted {
		h.overrideValue[summary.Name] = nil
	} else {
		value := summary.Value
		h.overrideValue[summary.Name] = &value
	}
}

// GetSession is the current session, or nil when the request carries no usable credential.
func (h *Helpers) GetSession(ctx context.Context) (*core.Object, error) {
	h.mu.Lock()
	pending := h.session
	if pending != nil {
		h.mu.Unlock()
		return pending.wait(ctx)
	}
	pending = newFuture[*core.Object]()
	h.session = pending
	h.mu.Unlock()
	session, err := h.loadSession(ctx)
	pending.settle(session, err)
	return session, err
}

func (h *Helpers) loadSession(ctx context.Context) (*core.Object, error) {
	iam, err := h.resolve(ctx)
	if err != nil {
		return nil, err
	}
	session, err := iam.GetSession(ctx, h.Credential())
	if err != nil {
		if IsAuthenticationError(err) {
			return nil, nil
		}
		return nil, err
	}
	return session, nil
}

// tenantFor is the explicit tenant when one was given, else the session's.
func (h *Helpers) tenantFor(ctx context.Context, explicit []string) (string, error) {
	if len(explicit) > 0 {
		return explicit[0], nil
	}
	session, err := h.GetSession(ctx)
	if err != nil {
		return "", err
	}
	return TenantOf(session), nil
}

// RequireSession is the current session; it fails with an IamRequestError 401 when signed out, 403 with a Reason when
// it must step up.
func (h *Helpers) RequireSession(ctx context.Context, stepUp *StepUpRequirement) (*core.Object, error) {
	current, err := h.GetSession(ctx)
	if err != nil {
		return nil, err
	}
	if current == nil {
		return nil, NewIamRequestError("UNAUTHENTICATED", "A session is required", 401)
	}
	if stepUp != nil {
		failure, err := CheckStepUp(current, *stepUp, h.clock())
		if err != nil {
			return nil, err
		}
		if failure != nil {
			return nil, NewIamRequestError(failure.Code, failure.Message, failure.Status, failure.Reason)
		}
	}
	return current, nil
}

// Require enforces one action (default resource: the tenant, `iam/{tenantId}`); it returns the server's refusal
// (401/403/429). tenantID, when given, replaces the session's tenant.
func (h *Helpers) Require(ctx context.Context, action string, resource *ResourceRef, tenantID ...string) error {
	tenant, err := h.tenantFor(ctx, tenantID)
	if err != nil {
		return err
	}
	if tenant == "" {
		return NewIamRequestError("UNAUTHENTICATED", "A session is required", 401)
	}
	iam, err := h.resolve(ctx)
	if err != nil {
		return err
	}
	target := ResourceRef{Type: "iam", ID: tenant}
	if resource != nil {
		target = *resource
	}
	return iam.Require(ctx, server.AuthorizationRequest{Credential: h.Credential(), TenantID: tenant, Action: action, Resource: target})
}

// Can is one advisory decision; checks made together share one authorizeMany call. False when signed out.
func (h *Helpers) Can(ctx context.Context, action string, resource *ResourceRef, tenantID ...string) (bool, error) {
	tenant, err := h.tenantFor(ctx, tenantID)
	if err != nil {
		return false, err
	}
	if tenant == "" {
		return false, nil
	}
	check := AuthorizeCheck{Action: action, Resource: ResourceRef{Type: "iam", ID: tenant}}
	if resource != nil {
		check.Resource = *resource
	}
	key := core.MustStringify([]any{tenant, action, check.Resource.Type, check.Resource.ID})
	h.mu.Lock()
	answer := h.answers[key]
	if answer == nil {
		answer = newFuture[bool]()
		if len(h.queue) == 0 {
			scheduleFlush(h.flush)
		}
		h.queue = append(h.queue, &queuedCheck{ctx: ctx, tenantID: tenant, check: check, answer: answer})
		h.answers[key] = answer
	}
	h.mu.Unlock()
	return answer.wait(ctx)
}

// flush sends the queued advisory checks, per tenant, 50 at a time.
func (h *Helpers) flush() {
	h.mu.Lock()
	batch := h.queue
	h.queue = nil
	h.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	ctx := batch[0].ctx
	var tenants []string
	byTenant := map[string][]*queuedCheck{}
	for _, item := range batch {
		if _, ok := byTenant[item.tenantID]; !ok {
			tenants = append(tenants, item.tenantID)
		}
		byTenant[item.tenantID] = append(byTenant[item.tenantID], item)
	}
	iam, err := h.resolve(ctx)
	if err != nil {
		for _, item := range batch {
			item.answer.settle(false, err)
		}
		return
	}
	caller := h.Credential()
	for _, tenantID := range tenants {
		items := byTenant[tenantID]
		for start := 0; start < len(items); start += 50 {
			slice := items[start:min(start+50, len(items))]
			checks := make([]server.AuthorizationCheck, len(slice))
			for index, item := range slice {
				checks[index] = server.AuthorizationCheck{Action: item.check.Action, Resource: item.check.Resource}
			}
			answer, err := iam.AuthorizeMany(ctx, server.BatchAuthorizationRequest{Credential: caller, TenantID: tenantID, Checks: checks})
			if err != nil {
				_, coded := ErrorCode(err)
				for _, item := range slice {
					if coded {
						item.answer.settle(false, nil)
					} else {
						item.answer.settle(false, err)
					}
				}
				continue
			}
			results := batchResults(answer)
			for index, item := range slice {
				allowed := false
				if index < len(results) && results[index] != nil {
					allowed, _ = results[index].Get("allowed").(bool)
				}
				item.answer.settle(allowed, nil)
			}
		}
	}
}

func batchResults(answer *core.Object) []*core.Object {
	if answer == nil {
		return nil
	}
	list, _ := answer.Get("results").([]any)
	results := make([]*core.Object, len(list))
	for index, item := range list {
		results[index], _ = item.(*core.Object)
	}
	return results
}

// Check is one check of Authorize; a nil Resource is the tenant itself.
type Check struct {
	Action   string
	Resource *ResourceRef
}

// Authorize is advisory decisions for several checks; every check is denied (UNAUTHENTICATED) when signed out.
func (h *Helpers) Authorize(ctx context.Context, checks []Check, tenantID ...string) ([]AuthorizeResult, error) {
	tenant, err := h.tenantFor(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	resolved := make([]AuthorizeCheck, len(checks))
	for index, check := range checks {
		resolved[index] = AuthorizeCheck{Action: check.Action, Resource: ResourceRef{Type: "iam", ID: tenant}}
		if check.Resource != nil {
			resolved[index].Resource = *check.Resource
		}
	}
	results := make([]AuthorizeResult, 0, len(resolved))
	if tenant == "" {
		for _, check := range resolved {
			results = append(results, AuthorizeResult{Action: check.Action, Resource: check.Resource, Allowed: false, Reason: "UNAUTHENTICATED"})
		}
		return results, nil
	}
	iam, err := h.resolve(ctx)
	if err != nil {
		return nil, err
	}
	for start := 0; start < len(resolved); start += 50 {
		slice := resolved[start:min(start+50, len(resolved))]
		request := make([]server.AuthorizationCheck, len(slice))
		for index, check := range slice {
			request[index] = server.AuthorizationCheck{Action: check.Action, Resource: check.Resource}
		}
		answer, err := iam.AuthorizeMany(ctx, server.BatchAuthorizationRequest{Credential: h.Credential(), TenantID: tenant, Checks: request})
		if err != nil {
			code, coded := ErrorCode(err)
			if !coded {
				return nil, err
			}
			for _, check := range slice {
				results = append(results, AuthorizeResult{Action: check.Action, Resource: check.Resource, Allowed: false, Reason: code})
			}
			continue
		}
		answers := batchResults(answer)
		for index, check := range slice {
			result := AuthorizeResult{Action: check.Action, Resource: check.Resource, Allowed: false, Reason: "DENIED"}
			if index < len(answers) && answers[index] != nil {
				if allowed, ok := answers[index].Get("allowed").(bool); ok {
					result.Allowed = allowed
				}
				if value, present := answers[index].Lookup("reason"); present && value != nil && !core.IsUndefined(value) {
					result.Reason, _ = value.(string)
				}
			}
			results = append(results, result)
		}
	}
	return results, nil
}

// ListAccessibleInput is the input of ListAccessible ("" TenantID: the session's tenant).
type ListAccessibleInput struct {
	Action   string
	Type     string
	TenantID string
	Limit    *float64
	Offset   *float64
}

// ListAccessible is the registered resources of a managed type the caller may act on.
func (h *Helpers) ListAccessible(ctx context.Context, input ListAccessibleInput) (*core.Object, error) {
	iam, err := h.resolve(ctx)
	if err != nil {
		return nil, err
	}
	lister, ok := iam.(AccessibleLister)
	if !ok {
		return nil, errors.New("This IAM server does not list accessible resources")
	}
	var explicit []string
	if input.TenantID != "" {
		explicit = []string{input.TenantID}
	}
	tenant, err := h.tenantFor(ctx, explicit)
	if err != nil {
		return nil, err
	}
	if tenant == "" {
		return core.NewObject("resources", []any{}, "total", float64(0)), nil
	}
	return lister.ListAccessible(ctx, server.AccessibleResourcesRequest{
		Credential: h.Credential(), TenantID: tenant, Action: input.Action, Type: input.Type, Limit: input.Limit, Offset: input.Offset,
	})
}

// PlanInput is the input of Plan ("" TenantID: the session's tenant).
type PlanInput struct {
	Action   string
	Type     string
	TenantID string
}

// Plan is which resources of a type the caller may perform an action on, as a filter for your own query (compile it
// with the core filter compilers). It plans `never` when signed out.
func (h *Helpers) Plan(ctx context.Context, input PlanInput) (*core.Object, error) {
	iam, err := h.resolve(ctx)
	if err != nil {
		return nil, err
	}
	planner, ok := iam.(ResourcePlanner)
	if !ok {
		return nil, errors.New("This IAM server does not plan resources")
	}
	var explicit []string
	if input.TenantID != "" {
		explicit = []string{input.TenantID}
	}
	tenant, err := h.tenantFor(ctx, explicit)
	if err != nil {
		return nil, err
	}
	if tenant == "" {
		return core.NewObject(
			"tenantId", "", "action", input.Action, "type", input.Type, "kind", "never",
			"filter", core.NewObject("kind", "false"),
		), nil
	}
	return planner.PlanResources(ctx, server.PlanResourcesRequest{Credential: h.Credential(), TenantID: tenant, Action: input.Action, Type: input.Type})
}

// Assertion is a short-lived signed assertion about the caller for a downstream service.
func (h *Helpers) Assertion(ctx context.Context, input AssertionInput) (*core.Object, error) {
	iam, err := h.resolve(ctx)
	if err != nil {
		return nil, err
	}
	issuer, ok := iam.(AssertionIssuer)
	if !ok {
		return nil, errors.New("This IAM server does not issue assertions")
	}
	body := core.NewObject("tenantId", input.TenantID, "audience", input.Audience)
	if input.TTLSeconds != nil {
		body.Set("ttlSeconds", *input.TTLSeconds)
	}
	if input.Claims != nil {
		body.Set("claims", input.Claims)
	}
	return issuer.IssueAssertion(ctx, h.Credential(), body)
}

// Client is the in-process client: its transport is the IAM handler in this process, and Set-Cookie answers go on
// this response.
func (h *Helpers) Client() *Client {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.client == nil {
		h.client = &Client{helpers: h}
	}
	return h.client
}

// SignOut ends the session on the server and clears its cookie; it never fails for an already-dead session.
func (h *Helpers) SignOut(ctx context.Context) error {
	cookie, _ := headerGet(h.Header(), "cookie")
	present := ParseCookieHeader(cookie)
	if _, err := h.Client().Call(ctx, "auth/signOut", nil); err != nil {
		if _, coded := ErrorCode(err); !coded {
			return err
		}
	}
	iam, err := h.resolve(ctx)
	if err != nil {
		return err
	}
	secure := h.binding.URL != nil && h.binding.URL.Scheme == "https"
	if provider, ok := iam.(EndpointProvider); ok {
		secure = provider.IamEndpoint().Secure
	}
	for _, name := range sessionCookies {
		h.mu.Lock()
		value, overridden := h.overrideValue[name]
		h.mu.Unlock()
		if present.Has(name) && (!overridden || value != nil) {
			attributes := ""
			if secure || strings.HasPrefix(name, "__Host-") {
				attributes = "; Secure"
			}
			h.setCookie(name + "=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax" + attributes)
		}
	}
	h.forget()
	return nil
}

// ErrorBody is the IAM API's JSON error envelope, used by every integration for refusals.
func ErrorBody(code, message string) string {
	return core.MustStringify(core.NewObject("error", core.NewObject("code", code, "message", message)))
}

// RefusalRequest is the request a refusal answers.
type RefusalRequest struct {
	URL    *url.URL
	Header http.Header
	Method string
}

// Pages are where page navigations go on a refusal.
type Pages struct {
	// LoginPath receives signed-out page navigations (`?next=`).
	LoginPath string
	// StepUpPath receives page navigations whose session must step up (`?next=`, `?reason=`).
	StepUpPath string
}

// RefusalAnswer is how a guard answers a refusal: a redirect (Redirect set) or a JSON body with a status.
type RefusalAnswer struct {
	Redirect string
	Status   int
	Body     string
}

// RefusalResponse is how a guard should answer a refusal: a redirect for page navigations when a page is configured,
// else JSON.
func RefusalResponse(refusal Refusal, request RefusalRequest, pages Pages) RefusalAnswer {
	accept, _ := headerGet(request.Header, "accept")
	navigation := (request.Method == "GET" || request.Method == "HEAD") && strings.Contains(accept, "text/html")
	if navigation {
		target := "/"
		if request.URL != nil {
			target = request.URL.EscapedPath()
			if target == "" {
				target = "/"
			}
			if request.URL.RawQuery != "" {
				target += "?" + request.URL.RawQuery
			}
		}
		next := SafeRedirectPath(target)
		if refusal.Status == 401 && pages.LoginPath != "" {
			return RefusalAnswer{Redirect: WithQuery(pages.LoginPath, QueryParam{"next", next})}
		}
		if refusal.Reason != "" && pages.StepUpPath != "" {
			return RefusalAnswer{Redirect: WithQuery(pages.StepUpPath, QueryParam{"next", next}, QueryParam{"reason", refusal.Reason})}
		}
	}
	return RefusalAnswer{Status: refusal.Status, Body: ErrorBody(refusal.Code, refusal.Message)}
}

var safeMethods = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true}

// OriginRequest is the request CheckRequestOrigin looks at (URL absolute: the scheme and host it was sent to).
type OriginRequest struct {
	Method string
	URL    *url.URL
	Header http.Header
}

// CheckRequestOrigin is the CSRF boundary for application routes: a state-changing request authenticated by the
// session cookie (no Authorization header) must come from this application's origin, the IAM origin, or a trusted
// origin. Session cookies are SameSite=Lax, which still sends them from sibling subdomains, so the Origin check
// matters. It returns the refusal, or nil when the request may proceed. "" entries of trustedOrigins are skipped.
func CheckRequestOrigin(request OriginRequest, trustedOrigins []string) *IamRequestError {
	header := request.Header
	if header == nil {
		header = http.Header{}
	}
	if _, present := headerGet(header, "authorization"); safeMethods[strings.ToUpper(request.Method)] || present {
		return nil
	}
	cookie, _ := headerGet(header, "cookie")
	cookies := ParseCookieHeader(cookie)
	carries := false
	for _, name := range sessionCookies {
		if cookies.Has(name) {
			carries = true
		}
	}
	if !carries {
		return nil
	}
	if site, _ := headerGet(header, "sec-fetch-site"); site == "same-origin" {
		return nil
	}
	origin, present := headerGet(header, "origin")
	if !present || origin == "" {
		return NewIamRequestError("CSRF_REJECTED", "Cookie requests require Origin", 403)
	}
	// `null` is what sandboxed frames, redirects and no-referrer posts send, and also the `.origin` of non-http trusted
	// entries such as `capacitor://localhost`, so it must never match anything.
	if origin == "null" {
		return NewIamRequestError("UNTRUSTED_ORIGIN", "Origin is not trusted", 403)
	}
	forwardedHost := firstListValue(header, "x-forwarded-host")
	forwardedProto := firstListValue(header, "x-forwarded-proto")
	own := []string{"", ""}
	if request.URL != nil {
		own[0] = URLOrigin(request.URL.Scheme + "://" + request.URL.Host + "/")
		if forwardedHost != nil {
			proto := request.URL.Scheme
			if forwardedProto != nil {
				proto = *forwardedProto
			}
			own[1] = proto + "://" + *forwardedHost
		}
	}
	for _, entry := range append(own, trustedOrigins...) {
		if entry == "" {
			continue
		}
		if resolved := URLOrigin(entry); resolved != "" && resolved == origin {
			return nil
		}
	}
	return NewIamRequestError("UNTRUSTED_ORIGIN", "Origin is not trusted", 403)
}

// firstListValue is `headers.get(name)?.split(',')[0]?.trim()`: nil when the header is absent.
func firstListValue(header http.Header, name string) *string {
	value, present := headerGet(header, name)
	if !present {
		return nil
	}
	first, _, _ := strings.Cut(value, ",")
	first = core.JSTrim(first)
	return &first
}

// URLOrigin is `new URL(value).origin`: "null" for a URL without a tuple origin, "" when value is not an absolute
// URL.
func URLOrigin(value string) string {
	parsed, err := auth.ParseFetchURL(value)
	if err != nil {
		return ""
	}
	switch parsed.Protocol {
	case "http:", "https:", "ws:", "wss:", "ftp:":
	default:
		return "null"
	}
	origin := parsed.Protocol + "//" + parsed.Hostname
	if parsed.Port != "" {
		origin += ":" + parsed.Port
	}
	return origin
}

// GuardSpec is what a guard checks: a session, then optional step-up, then an optional authorization.
type GuardSpec[Req any] struct {
	StepUp    *StepUpRequirement
	Authorize *AuthorizeRule[Req]
}

// AuthorizeRule is the authorization a guard requires.
type AuthorizeRule[Req any] struct {
	Action string
	// Resource defaults to the tenant itself (`iam/{tenantId}`).
	Resource func(request Req, session *core.Object) (ResourceRef, error)
	// TenantID defaults to the session's tenant.
	TenantID func(request Req, session *core.Object) (string, error)
}

// AuthorizeSpec is the options of an authorize guard: the rule without its action, and an optional step-up.
type AuthorizeSpec[Req any] struct {
	StepUp   *StepUpRequirement
	Resource func(request Req, session *core.Object) (ResourceRef, error)
	TenantID func(request Req, session *core.Object) (string, error)
}

// Guard is the GuardSpec of an authorize guard for action.
func (s AuthorizeSpec[Req]) Guard(action string) GuardSpec[Req] {
	return GuardSpec[Req]{StepUp: s.StepUp, Authorize: &AuthorizeRule[Req]{Action: action, Resource: s.Resource, TenantID: s.TenantID}}
}

// GuardOptions are the options every framework integration shares for its guards.
type GuardOptions struct {
	// TrustedOrigins are origins besides the request's own and the IAM origin that may send cookie-authenticated
	// unsafe requests.
	TrustedOrigins []string
	// CSRF checks Origin on cookie-authenticated POST/PUT/PATCH/DELETE requests in guards (default true).
	CSRF *bool
}

// OriginCheck is the request a guard checks the Origin of, with the trusted origins.
type OriginCheck struct {
	Method         string
	URL            *url.URL
	Header         http.Header
	TrustedOrigins []string
}

// EnforceGuard runs a guard; it answers the session or the refusal (an IamRequestError or the server's IamError).
// With origin, a cookie-authenticated unsafe request from an untrusted origin is refused first.
func EnforceGuard[Req any](ctx context.Context, helpers *Helpers, request Req, spec GuardSpec[Req], origin *OriginCheck) (*core.Object, error) {
	if origin != nil {
		if refusal := CheckRequestOrigin(OriginRequest{Method: origin.Method, URL: origin.URL, Header: origin.Header}, origin.TrustedOrigins); refusal != nil {
			return nil, refusal
		}
	}
	session, err := helpers.RequireSession(ctx, spec.StepUp)
	if err != nil {
		return nil, err
	}
	rule := spec.Authorize
	if rule != nil {
		tenantID := TenantOf(session)
		if rule.TenantID != nil {
			tenantID, err = rule.TenantID(request, session)
			if err != nil {
				return nil, err
			}
		}
		if tenantID == "" {
			return nil, NewIamRequestError("INVALID_INPUT", "No tenant to authorize in", 400)
		}
		resource := ResourceRef{Type: "iam", ID: tenantID}
		if rule.Resource != nil {
			resource, err = rule.Resource(request, session)
			if err != nil {
				return nil, err
			}
		}
		if err := helpers.Require(ctx, rule.Action, &resource, tenantID); err != nil {
			return nil, err
		}
	}
	return session, nil
}
