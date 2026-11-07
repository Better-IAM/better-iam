package server

// Port of packages/server/src/http.ts: the HTTP transport over the provisioning API (the CSRF boundary, cookies,
// CORS, body limits, the operational GET routes, protocol mounts) and the authentication API group (createAuthApi).
//
// TypeScript has two transports: `handler` (fetch Request -> Response) and `nodeHandler` (Node's req/res, which
// reads the body under a limit and then calls `handler`). Go has both: HTTPTransport.Handle is `handler` and
// HTTPTransport.ServeHTTP (an http.Handler) is `nodeHandler`.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// PublicAuthMethods are the auth methods called with the body alone. HTTP endpoints are mapped explicitly:
// infrastructure helpers are never remotely callable.
var PublicAuthMethods = newOrderedSet(
	"signUp", "signIn", "requestEmailVerification", "verifyEmail", "requestPasswordReset", "resetPassword",
	"confirmEmailChange", "startPasswordless", "finishPasswordless", "beginMfa", "confirmMfa", "verifyMfa",
	"requestMfaCode", "recoverMfa", "beginPasskeyAuthentication", "finishPasskeyAuthentication", "beginPasskeyMfa",
	"finishPasskeyMfa",
)

// AuthenticatedAuthMethods are the auth methods called with (credential, body).
var AuthenticatedAuthMethods = newOrderedSet(
	"signOut", "getSession", "listSessions", "revokeSession", "revokeOtherSessions", "changePassword",
	"requestEmailChange", "beginPasskeyRegistration", "finishPasskeyRegistration", "startPhoneVerification",
	"confirmPhoneVerification", "reauthenticate", "listPasskeys", "deletePasskey", "renamePasskey",
	"regenerateRecoveryCodes", "disableMfa", "listTrustedDevices", "revokeTrustedDevice", "revokeTrustedDevices",
	"listSecurityEvents", "mfaStatus",
)

// RouteGroups are the API groups the router serves.
var RouteGroups = newOrderedSet(
	"tenants", "identities", "policies", "roles", "bindings", "authorities", "groups", "actions", "resourceTypes",
	"resources", "serviceAccounts", "credentials", "trust", "links", "root", "audit", "accessRequests", "webhooks",
	"relationships", "assertions", "domains", "config", "analysis", "certifications", "sod", "reports", "packages",
	"security", "roleMining", "impact", "invariants", "agreements", "accessPaths", "sts", "oidcProviders", "features",
	"onboarding", "hostnames", "agents", "delegations", "inference", "teams", "departments", "billing", "keys", "pki",
	"protection", "vault", "privacy", "ssh", "threats", "workflows", "compliance", "applications",
	"verifiableCredentials", "ldap", "devices", "filters", "signals", "quotas", "licenses", "guests", "clearances",
)

// PublicAPIMethods are the API methods called with the body alone (their credential is in the body, or none).
var PublicAPIMethods = newOrderedSet(
	"tenants/acceptInvitation", "tenants/lookup", "domains/discover", "identities/acceptInvitation",
	// The external OIDC token is the credential; the exchange is rate limited per trust before any lookup.
	"sts/assumeRoleWithWebIdentity",
	// Data-subject requests from people without an account: only when the organization turned public intake on.
	"privacy/submitPublic", "privacy/confirmPublic",
	// SSH hosts: the one-time join token or the host's renewal token is the credential.
	"ssh/enrollHost", "ssh/syncHost", "ssh/trust", "ssh/revocationList",
	// Verifiable credentials: proof nonces, presentation checks and issuer metadata.
	"verifiableCredentials/nonce", "verifiableCredentials/verify", "verifiableCredentials/issuerMetadata",
	// Guest invitations: the emailed token is the credential.
	"guests/redeem",
)

// tenantBoundPublicMethods act in one organization named by tenantId (pinned to the request's host); every public
// auth method is tenant-bound too.
var tenantBoundPublicMethods = newOrderedSet(
	"tenants/acceptInvitation", "identities/acceptInvitation", "sts/assumeRoleWithWebIdentity",
	"privacy/submitPublic", "privacy/confirmPublic", "ssh/trust", "ssh/revocationList", "guests/redeem",
)

// sessionCookieRoutes answer with the browser's new session, so their answer sets the session cookie.
var sessionCookieRoutes = newOrderedSet(
	"auth/signIn", "auth/verifyMfa", "auth/confirmMfa", "auth/recoverMfa", "auth/finishPasswordless",
	"auth/finishPasskeyAuthentication", "auth/finishPasskeyMfa", "auth/reauthenticate", "tenants/acceptInvitation",
	"identities/acceptInvitation", "guests/redeem", "links/switch",
)

// deviceTokenRoutes receive the trusted-device cookie as body.deviceToken when the body has none.
var deviceTokenRoutes = newOrderedSet("auth/signIn", "auth/finishPasswordless")

// ProtocolService is a protocol mounted under a base path for both transports (OAuth provider, SAML, SCIM, ...).
type ProtocolService struct {
	BasePath string
	// Handler answers a request (fetch style) and returns true, or false to pass it on. Its JSON answers carrying
	// `token` and `session.expiresAt` set the session cookie, as the TypeScript handler's answers do.
	Handler func(w http.ResponseWriter, r *http.Request) bool
	// NodeHandler serves every request under BasePath (and /.well-known/oauth-authorization-server{BasePath}).
	NodeHandler http.Handler
}

// Response is what the fetch-style transport answers (a TypeScript Response).
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

func (r *Response) ok() bool { return r.Status >= 200 && r.Status < 300 }

// hardened are the headers every JSON answer carries: never cached, never sniffed, never leaking the URL.
func hardened() http.Header {
	return http.Header{
		"Cache-Control":          {"no-store"},
		"X-Content-Type-Options": {"nosniff"},
		"Referrer-Policy":        {"no-referrer"},
	}
}

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// headerValue is Headers#get: every value of the header joined with ", " ("; " for Cookie); ok is false when absent.
func headerValue(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) == 0 {
		return "", false
	}
	if strings.EqualFold(name, "cookie") {
		return strings.Join(values, "; "), true
	}
	return strings.Join(values, ", "), true
}

// jsonResponse is Response.json(value, { status, headers }).
func jsonResponse(value any, status int, header http.Header) *Response {
	if header == nil {
		header = http.Header{}
	}
	model, err := ToModel(value)
	if err != nil {
		model = nil
	}
	text, ok, err := core.Stringify(model)
	if err != nil || !ok {
		text = "null"
	}
	if header.Get("Content-Type") == "" {
		header.Set("Content-Type", "application/json")
	}
	return &Response{Status: status, Header: header, Body: []byte(text)}
}

// retryAfterOf is the retry hint an error carries (RATE_LIMITED, QUOTA_EXCEEDED, ...): 0 for none.
func retryAfterOf(err error) float64 {
	var limited *auth.RateLimitedError
	if errors.As(err, &limited) {
		return float64(limited.RetryAfterMs)
	}
	var hinted interface{ RetryAfter() float64 }
	if errors.As(err, &hinted) {
		return hinted.RetryAfter()
	}
	return 0
}

// errorResponse is the JSON error answer: { error: { code, message, retryAfterMs?, region?, location? } }.
func errorResponse(err error) *Response {
	var known *core.IamError
	isKnown := errors.As(err, &known)
	header := hardened()
	var retryAfterMs float64
	if isKnown {
		if hint := retryAfterOf(err); hint > 0 {
			retryAfterMs = hint
			// Rate-limited callers learn when to come back (RFC 9110 Retry-After, in seconds).
			header.Set("Retry-After", core.NumberString(math.Ceil(retryAfterMs/1000)))
		}
	}
	body := core.NewObject()
	if isKnown {
		body.Set("code", known.Code).Set("message", known.Message)
	} else {
		body.Set("code", "INTERNAL_ERROR").Set("message", "Internal server error")
	}
	if retryAfterMs > 0 {
		body.Set("retryAfterMs", retryAfterMs)
	}
	// A request for an organization another region serves learns where to go instead (WRONG_REGION).
	var wrong *WrongRegionError
	if errors.As(err, &wrong) {
		body.Set("region", wrong.Region)
		if wrong.Location != nil && *wrong.Location != "" {
			body.Set("location", *wrong.Location)
		}
	}
	status := 500
	if isKnown {
		status = known.Status
	}
	return jsonResponse(core.NewObject("error", body), status, header)
}

// publicResult drops tokenHash and uniqueKey from a top-level `session` object (defence in depth).
func publicResult(result any) any {
	object, ok := result.(*core.Object)
	if !ok || object == nil || !object.Has("session") {
		return result
	}
	session, ok := object.Get("session").(*core.Object)
	if !ok || session == nil || !(session.Has("tokenHash") || session.Has("uniqueKey")) {
		return result
	}
	rest := session.Clone()
	rest.Delete("tokenHash")
	rest.Delete("uniqueKey")
	copy := object.Clone()
	copy.Set("session", rest)
	return copy
}

// HTTPExtras are the metrics settings createHttp receives.
type HTTPExtras struct {
	Metrics       *MetricsCollector
	MetricsToken  string
	MetricsGauges bool
}

// HTTPTransport serves the IAM HTTP surface (createHttp).
type HTTPTransport struct {
	server       *ServerContext
	api          *API
	authAPI      *AuthAPI
	extras       HTTPExtras
	secure       bool
	sameSite     string
	persistent   *bool
	deviceCookie string
}

// CreateHTTP builds the transport; it refuses invalid http options with INVALID_CONFIG.
func CreateHTTP(server *ServerContext, api *API, authAPI *AuthAPI, extras HTTPExtras) (*HTTPTransport, error) {
	value := member(OptionsValue(server.Options), "http")
	sameSite := "lax"
	if raw := member(value, "cookieSameSite"); !nullish(raw) {
		if raw != "lax" && raw != "strict" {
			return nil, invalidConfig("http.cookieSameSite must be lax or strict")
		}
		sameSite = raw.(string)
	}
	if sameSite != "lax" && sameSite != "strict" {
		return nil, invalidConfig("http.cookieSameSite must be lax or strict")
	}
	var persistent *bool
	if raw := member(value, "persistentCookies"); !isUndefined(raw) {
		flag, isBool := raw.(bool)
		if !isBool {
			return nil, invalidConfig("http.persistentCookies must be a boolean")
		}
		persistent = &flag
	}
	secure := server.Config.BaseURL.Protocol == "https:"
	prefix := ""
	if secure {
		prefix = "__Host-"
	}
	return &HTTPTransport{
		server: server, api: api, authAPI: authAPI, extras: extras, secure: secure, sameSite: sameSite,
		persistent: persistent, deviceCookie: prefix + "better-iam.device",
	}, nil
}

// cookieNamed is `{__Host-}{name}={encoded}; HttpOnly; {Secure; }SameSite=...; Path=/{; Max-Age=n}`.
func (h *HTTPTransport) cookieNamed(name, raw string, maxAge *float64) string {
	var b strings.Builder
	if h.secure {
		b.WriteString("__Host-")
	}
	b.WriteString(name + "=" + encodeURIComponent(raw) + "; HttpOnly; ")
	if h.secure {
		b.WriteString("Secure; ")
	}
	if h.sameSite == "strict" {
		b.WriteString("SameSite=Strict")
	} else {
		b.WriteString("SameSite=Lax")
	}
	b.WriteString("; Path=/")
	if maxAge != nil {
		b.WriteString("; Max-Age=" + core.NumberString(*maxAge))
	}
	return b.String()
}

func (h *HTTPTransport) cookie(raw string, maxAge *float64) string {
	return h.cookieNamed("better-iam.session", raw, maxAge)
}

// secondsUntil is the whole seconds left until expiresAt on the injected clock (NaN for a non-number).
func (h *HTTPTransport) secondsUntil(expiresAt any) float64 {
	return math.Max(0, math.Floor((jsNumber(expiresAt)-float64(h.server.Now()))/1000))
}

func (h *HTTPTransport) sessionCookie(token, expiresAt any, persistent bool) string {
	if !persistent {
		return h.cookie(jsString(token), nil)
	}
	seconds := h.secondsUntil(expiresAt)
	return h.cookie(jsString(token), &seconds)
}

func (h *HTTPTransport) persistentFor(header http.Header) bool {
	value, _ := headerValue(header, "x-better-iam-persistent")
	if value == "1" {
		return true
	}
	if value == "0" {
		return false
	}
	if h.persistent != nil {
		return *h.persistent
	}
	return true
}

func (h *HTTPTransport) deviceCookieFor(raw string, expiresAt any) string {
	seconds := h.secondsUntil(expiresAt)
	return h.cookieNamed("better-iam.device", raw, &seconds)
}

func (h *HTTPTransport) deviceCookieValue(header http.Header) (string, bool) {
	value, present := headerValue(header, "cookie")
	if !present {
		return "", false
	}
	for _, part := range strings.Split(value, ";") {
		part = core.JSTrim(part)
		if strings.HasPrefix(part, h.deviceCookie+"=") {
			return part[len(h.deviceCookie)+1:], true
		}
	}
	return "", false
}

// recorder buffers a protocol mount's answer, so the session cookie can be added to it.
type recorder struct {
	header http.Header
	status int
	body   bytes.Buffer
	wrote  bool
}

func (r *recorder) Header() http.Header { return r.header }
func (r *recorder) WriteHeader(status int) {
	if !r.wrote {
		r.status, r.wrote = status, true
	}
}
func (r *recorder) Write(data []byte) (int, error) {
	r.WriteHeader(http.StatusOK)
	return r.body.Write(data)
}

// followableRedirect checks a redirect a protocol asks for (`x-better-iam-redirect`, the SAML ACS's `afterSignIn`): a
// path on this site or a URL on this deployment's origin or one of `trustedOrigins`. Anything else is not followed
// (ok false).
func (h *HTTPTransport) followableRedirect(value string, present bool) (string, bool) {
	if !present || value == "" || utf16Len(value) > 4096 {
		return "", false
	}
	for index := 0; index < len(value); index++ {
		if c := value[index]; c <= 0x1f || c == 0x7f || c == '\\' {
			return "", false
		}
	}
	if strings.HasPrefix(value, "/") {
		if strings.HasPrefix(value, "//") {
			return "", false
		}
		return value, true
	}
	target, err := auth.ParseFetchURL(value)
	if err != nil {
		return "", false
	}
	if target.User != nil {
		if password, _ := target.User.Password(); target.User.Username() != "" || password != "" {
			return "", false
		}
	}
	if !h.server.Config.TrustedOrigin(urlOrigin(target)) {
		return "", false
	}
	return target.Href, true
}

// protocolResponse runs the fetch-style protocol mounts; a JSON answer with `token` and `session.expiresAt` sets the
// session cookie, and a followable `x-better-iam-redirect` turns the answer into a 303 to that page (carrying the
// protocol's cookies and the session cookie, never the body: the token stays out of the page).
func (h *HTTPTransport) protocolResponse(request *http.Request) *Response {
	for _, protocol := range h.server.MountedProtocols {
		if protocol.Handle == nil || protocol.Node {
			continue
		}
		buffer := &recorder{header: http.Header{}}
		if !protocol.Handle(buffer, request) {
			continue
		}
		if !buffer.wrote {
			buffer.status = http.StatusOK
		}
		response := &Response{Status: buffer.status, Header: buffer.header, Body: buffer.body.Bytes()}
		hint, hinted := headerValue(response.Header, "x-better-iam-redirect")
		redirect, follow := h.followableRedirect(hint, hinted)
		if hinted {
			response.Header.Del("x-better-iam-redirect")
		}
		cookie := ""
		if response.ok() && strings.Contains(response.Header.Get("Content-Type"), "application/json") {
			if parsed, err := core.ParseJSON(response.Body); err == nil {
				if result, isObject := parsed.(*core.Object); isObject {
					token, isToken := result.Get("token").(string)
					expiresAt, isNumber := member(result.Get("session"), "expiresAt").(float64)
					if isToken && isNumber {
						cookie = h.sessionCookie(token, expiresAt, h.persistentFor(request.Header))
					}
				}
			}
		}
		if follow {
			headers := http.Header{}
			headers.Set("Location", redirect)
			headers.Set("Cache-Control", "no-store")
			for _, value := range response.Header.Values("Set-Cookie") {
				headers.Add("Set-Cookie", value)
			}
			if cookie != "" {
				headers.Add("Set-Cookie", cookie)
			}
			return &Response{Status: http.StatusSeeOther, Header: headers}
		}
		if cookie != "" {
			response.Header.Add("Set-Cookie", cookie)
		}
		return response
	}
	return nil
}

// authorizationRequestInput validates the authorize body as the router does.
func (h *HTTPTransport) dispatch(ctx context.Context, path string, body *core.Object, credential core.CredentialInput) (any, error) {
	operations := h.server.Operations
	switch path {
	case "authorize":
		resource, err := Object(body.Get("resource"))
		if err != nil {
			return nil, err
		}
		tenantID, err := Text(body.Get("tenantId"), "tenantId")
		if err != nil {
			return nil, err
		}
		action, err := Text(body.Get("action"), "action")
		if err != nil {
			return nil, err
		}
		resourceType, err := Text(resource.Get("type"), "resource type")
		if err != nil {
			return nil, err
		}
		resourceID, err := Text(resource.Get("id"), "resource id")
		if err != nil {
			return nil, err
		}
		return anyResult(operations.Authorize(ctx, AuthorizationRequest{
			Credential: credential, TenantID: tenantID, Action: action,
			Resource: ResourceTarget{Type: resourceType, ID: resourceID},
		}))
	case "authorizeMany":
		tenantID, err := Text(body.Get("tenantId"), "tenantId")
		if err != nil {
			return nil, err
		}
		results, err := operations.AuthorizeMany(ctx, BatchAuthorizationRequest{
			Credential: credential, TenantID: tenantID, ChecksValue: body.Get("checks"),
		})
		if err != nil {
			return nil, err
		}
		return batchResults(results), nil
	case "listAccessible":
		tenantID, err := Text(body.Get("tenantId"), "tenantId")
		if err != nil {
			return nil, err
		}
		action, err := Text(body.Get("action"), "action")
		if err != nil {
			return nil, err
		}
		resourceType, err := Text(body.Get("type"), "resource type", 64)
		if err != nil {
			return nil, err
		}
		accessible, err := operations.ListAccessible(ctx, AccessibleResourcesRequest{
			Credential: credential, TenantID: tenantID, Action: action, Type: resourceType,
			LimitValue: body.Get("limit"), OffsetValue: body.Get("offset"),
		})
		if err != nil {
			return nil, err
		}
		return accessible.Model(), nil
	}
	if strings.HasPrefix(path, "plugins/") {
		parts := strings.Split(path, "/")
		var pluginID any = core.Undefined
		if len(parts) > 1 {
			pluginID = parts[1]
		}
		id, err := Text(pluginID, "pluginId")
		if err != nil {
			return nil, err
		}
		rest := ""
		if len(parts) > 2 {
			rest = strings.Join(parts[2:], "/")
		}
		tenantID, err := Text(body.Get("tenantId"), "tenantId")
		if err != nil {
			return nil, err
		}
		return operations.CallPlugin(ctx, credential, PluginCall{PluginID: id, Path: rest, TenantID: tenantID, Input: body})
	}
	parts := strings.Split(path, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, endpointNotFound()
	}
	group, method := parts[0], parts[1]
	if group == "auth" {
		return h.dispatchAuth(ctx, method, body, credential)
	}
	if !RouteGroups.Has(group) {
		return nil, endpointNotFound()
	}
	call, found := rpcRoutes[path]
	if !found {
		return nil, endpointNotFound()
	}
	return call(ctx, h.api, credential, body)
}

func endpointNotFound() *core.IamError {
	return core.NewIamError("NOT_FOUND", "Endpoint not found", 404)
}

func (h *HTTPTransport) dispatchAuth(ctx context.Context, method string, body *core.Object, credential core.CredentialInput) (any, error) {
	if !PublicAuthMethods.Has(method) && !AuthenticatedAuthMethods.Has(method) {
		return nil, endpointNotFound()
	}
	// MFA enrollment takes either a sign-in challenge from the body or the request's own credential.
	if method == "beginMfa" {
		mfa := auth.MfaCredential{Credentials: &credential}
		if challenge, isString := body.Get("challenge").(string); isString {
			tenantID, err := Text(body.Get("tenantId"), "tenantId")
			if err != nil {
				return nil, err
			}
			mfa = auth.MfaCredential{TenantID: tenantID, Challenge: challenge}
		}
		out, err := h.authAPI.BeginMfa(ctx, mfa)
		return out.Value, err
	}
	if method == "confirmMfa" {
		challenge := core.NewObject()
		if raw := body.Get("credential"); truthy(raw) {
			object, err := Object(raw)
			if err != nil {
				return nil, err
			}
			challenge = object
		}
		mfa := auth.MfaCredential{Credentials: &credential}
		if value, isString := challenge.Get("challenge").(string); isString {
			tenantID, err := Text(challenge.Get("tenantId"), "tenantId")
			if err != nil {
				return nil, err
			}
			mfa = auth.MfaCredential{TenantID: tenantID, Challenge: value}
		}
		code, err := Text(body.Get("code"), "code")
		if err != nil {
			return nil, err
		}
		out, err := h.authAPI.ConfirmMfa(ctx, auth.ConfirmMfaInput{Credential: mfa, Code: code, RememberDevice: body.Get("rememberDevice") == true})
		return out.Value, err
	}
	call, found := rpcRoutes["auth/"+method]
	if !found {
		return nil, endpointNotFound()
	}
	return call(ctx, h.api, credential, body)
}

// routeName is the `http` span name: the route when the route table (or a registered plugin endpoint) knows it,
// otherwise `(unknown)`, so anonymous requests cannot mint unbounded span names.
func (h *HTTPTransport) routeName(path string) string {
	if path == "authorize" || path == "authorizeMany" || path == "listAccessible" {
		return path
	}
	parts := strings.Split(path, "/")
	group := parts[0]
	if group == "plugins" {
		method := ""
		if len(parts) > 1 {
			method = parts[1]
		}
		endpointPath := ""
		if len(parts) > 2 {
			endpointPath = strings.TrimPrefix(strings.Join(parts[2:], "/"), "/")
		}
		if pluginEndpoint(h.server.Plugins, method, endpointPath) != nil {
			return "plugins/" + method + "/" + endpointPath
		}
		return "(unknown)"
	}
	if len(parts) != 2 || group == "" || parts[1] == "" {
		return "(unknown)"
	}
	if group == "auth" {
		if PublicAuthMethods.Has(parts[1]) || AuthenticatedAuthMethods.Has(parts[1]) {
			return path
		}
		return "(unknown)"
	}
	if _, found := rpcRoutes[path]; found && RouteGroups.Has(group) {
		return path
	}
	return "(unknown)"
}

// pluginEndpoint finds a plugin's POST endpoint by path (leading slashes ignored).
func pluginEndpoint(plugins []*core.IamPlugin, pluginID, path string) *core.PluginEndpoint {
	for _, plugin := range plugins {
		if plugin.ID != pluginID {
			continue
		}
		for index := range plugin.Endpoints {
			endpoint := &plugin.Endpoints[index]
			if endpoint.Method == "POST" && strings.TrimPrefix(endpoint.Path, "/") == path {
				return endpoint
			}
		}
		return nil
	}
	return nil
}

// operational answers the GET routes: health, the session JWT keys, and metrics.
func (h *HTTPTransport) operational(ctx context.Context, pathname string, header http.Header) (*Response, error) {
	basePath := h.server.Config.BasePath
	if pathname == basePath+"/health" {
		started := h.server.Wall()
		// A lookup by primary key: an anonymous probe must not scan a collection. A missing row still proves the
		// database answers.
		if _, err := h.server.Store.Get(ctx, "tenants", "health-probe"); err != nil {
			return jsonResponse(core.NewObject("status", "unavailable", "database", "error", "time", float64(started)), 503, hardened()), nil
		}
		return jsonResponse(core.NewObject("status", "ok", "database", "ok", "latencyMs", float64(h.server.Wall()-started), "time", float64(started)), 200, hardened()), nil
	}
	if pathname == basePath+"/.well-known/jwks.json" {
		if h.server.SessionTokens == nil {
			return nil, endpointNotFound()
		}
		jwks, err := h.server.SessionTokens.PublicJwks()
		if err != nil {
			return nil, err
		}
		headers := hardened()
		headers.Set("Cache-Control", "public, max-age=300")
		headers.Set("Content-Type", "application/jwk-set+json")
		return jsonResponse(jwks, 200, headers), nil
	}
	if pathname == basePath+"/metrics" && h.extras.Metrics != nil && h.extras.MetricsToken != "" {
		provided, _ := headerValue(header, "authorization")
		expected := "Bearer " + h.extras.MetricsToken
		// Fixed-length digests: the comparison never reveals the token's length.
		left, right := sha256.Sum256([]byte(provided)), sha256.Sum256([]byte(expected))
		if subtle.ConstantTimeCompare(left[:], right[:]) != 1 {
			return nil, core.NewIamError("UNAUTHENTICATED", "A metrics bearer token is required", 401)
		}
		body := h.extras.Metrics.Render()
		if h.extras.MetricsGauges {
			gauges, err := h.storageGauges(ctx)
			if err != nil {
				return nil, err
			}
			body += gauges
		}
		headers := hardened()
		headers.Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		return &Response{Status: 200, Header: headers, Body: []byte(body)}, nil
	}
	return nil, endpointNotFound()
}

// storageGauges are point-in-time gauges read on each scrape: outbox backlog and unexpired sessions.
func (h *HTTPTransport) storageGauges(ctx context.Context) (string, error) {
	now := float64(h.server.Now())
	outbox, err := h.server.Store.Find(ctx, "outbox", nil, nil)
	if err != nil {
		return "", err
	}
	sessions, err := h.server.Store.Find(ctx, "sessions", nil, nil)
	if err != nil {
		return "", err
	}
	pending, failed := 0, 0
	for _, message := range outbox {
		if !truthy(message.Get("deliveredAt")) && !truthy(message.Get("failedAt")) {
			pending++
		}
		if truthy(message.Get("failedAt")) {
			failed++
		}
	}
	counts := map[string]int{}
	for _, session := range sessions {
		if jsNumber(session.Get("expiresAt")) > now {
			counts[jsString(session.Get("kind"))]++
		}
	}
	lines := []string{
		"# HELP better_iam_outbox_messages Delivery outbox messages by state.",
		"# TYPE better_iam_outbox_messages gauge",
		fmt.Sprintf(`better_iam_outbox_messages{state="pending"} %d`, pending),
		fmt.Sprintf(`better_iam_outbox_messages{state="failed"} %d`, failed),
		"# HELP better_iam_sessions_live Unexpired sessions by kind.",
		"# TYPE better_iam_sessions_live gauge",
	}
	for _, kind := range []string{"user", "api-key", "role", "session-token", "delegated"} {
		lines = append(lines, fmt.Sprintf(`better_iam_sessions_live{kind="%s"} %d`, kind, counts[kind]))
	}
	return strings.Join(append(lines, ""), "\n"), nil
}

// answerWith merges the answer headers (request ID, CORS) into a response.
func answerWith(response *Response, extra http.Header) *Response {
	for key, values := range extra {
		response.Header[key] = append([]string(nil), values...)
	}
	return response
}

// Handle is the fetch-style transport (TypeScript `handler`): it reads the body itself (at most 64 KiB).
func (h *HTTPTransport) Handle(r *http.Request) *Response {
	var body []byte
	var hasBody bool
	if r.Body != nil && r.Body != http.NoBody {
		hasBody = true
		data, err := io.ReadAll(io.LimitReader(r.Body, 65537))
		if err != nil {
			return errorResponse(err)
		}
		body = data
	}
	return h.handle(r, body, hasBody)
}

// handle answers one request whose body has been read (hasBody false: no body, which reads as `{}`).
func (h *HTTPTransport) handle(r *http.Request, body []byte, hasBody bool) *Response {
	ctx := r.Context()
	server := h.server
	requestID := ""
	if value, present := headerValue(r.Header, "x-request-id"); present && requestIDPattern.MatchString(value) {
		requestID = value
	}
	answerHeaders := http.Header{}
	if requestID != "" {
		answerHeaders.Set("X-Request-Id", requestID)
	}
	withRequestID := func(response *Response) *Response {
		if requestID != "" {
			response.Header.Set("X-Request-Id", requestID)
		}
		return response
	}
	client := ClientFromRequest(server.Options, r)
	mountCtx := server.Auth.WithClient(ctx, client)
	if mounted := h.protocolResponse(r.WithContext(mountCtx)); mounted != nil {
		return withRequestID(mounted)
	}
	response, err := h.route(r, body, hasBody, client, requestID, answerHeaders)
	if err != nil {
		return answerWith(errorResponse(err), answerHeaders)
	}
	return response
}

func (h *HTTPTransport) route(r *http.Request, rawBody []byte, hasBody bool, client *core.SessionClientInfo, requestID string, answerHeaders http.Header) (*Response, error) {
	ctx := r.Context()
	server := h.server
	basePath := server.Config.BasePath
	pathname := r.URL.EscapedPath()
	if !strings.HasPrefix(pathname, basePath+"/") {
		return answerWith(jsonResponse(core.NewObject("error", core.NewObject("code", "NOT_FOUND", "message", "Not found")), 404, nil), answerHeaders), nil
	}
	origin, hasOrigin := headerValue(r.Header, "origin")
	if hasOrigin && origin != "" {
		// Organization addresses (`hosts`) are trusted like the deployment's own origins.
		if !server.Config.TrustedOrigin(origin) {
			trusted, err := server.Hosts.TrustsOrigin(ctx, origin)
			if err != nil {
				return nil, err
			}
			if !trusted {
				return nil, core.NewIamError("UNTRUSTED_ORIGIN", "Origin is not trusted", 403)
			}
		}
		answerHeaders.Set("Access-Control-Allow-Origin", origin)
		answerHeaders.Set("Access-Control-Allow-Credentials", "true")
		answerHeaders.Set("Access-Control-Expose-Headers", "retry-after, x-request-id")
		answerHeaders.Set("Vary", "Origin")
	}
	if r.Method == http.MethodOptions {
		return answerWith(&Response{Status: 204, Header: http.Header{
			"Access-Control-Allow-Methods": {"GET, POST, OPTIONS"},
			"Access-Control-Allow-Headers": {"content-type, x-better-iam, authorization, x-request-id, x-better-iam-persistent, x-better-iam-device"},
		}}, answerHeaders), nil
	}
	if r.Method == http.MethodGet {
		response, err := h.operational(ctx, pathname, r.Header)
		if err != nil {
			return nil, err
		}
		return answerWith(response, answerHeaders), nil
	}
	if r.Method != http.MethodPost {
		return nil, core.NewIamError("METHOD_NOT_ALLOWED", "Use POST", 405)
	}
	contentType, _ := headerValue(r.Header, "content-type")
	marker, _ := headerValue(r.Header, "x-better-iam")
	if !strings.HasPrefix(strings.ToLower(contentType), "application/json") || marker != "1" {
		return nil, core.NewIamError("CSRF_REJECTED", "JSON and X-Better-IAM header required", 403)
	}
	if _, hasCookie := headerValue(r.Header, "cookie"); hasCookie && !hasOrigin {
		return nil, core.NewIamError("CSRF_REJECTED", "Cookie requests require Origin", 403)
	}
	raw := "{}"
	if hasBody {
		if len(rawBody) > 65536 {
			return nil, core.NewIamError("PAYLOAD_TOO_LARGE", "Request body too large", 413)
		}
		raw = decodeUTF8(rawBody)
	}
	parsed, err := core.ParseJSON([]byte(raw))
	if err != nil {
		return nil, invalidInput("Invalid JSON")
	}
	body, err := Object(parsed)
	if err != nil {
		return nil, invalidInput("Invalid JSON")
	}
	path := pathname[len(basePath)+1:]
	pathParts := strings.SplitN(path, "/", 3)
	group := pathParts[0]
	method := ""
	if len(pathParts) > 1 {
		method = pathParts[1]
	}
	publicRoute := PublicAPIMethods.Has(path)
	if group == "auth" {
		publicRoute = PublicAuthMethods.Has(method)
	}
	// On an organization's own address the request is pinned to that organization.
	pinned, err := server.Hosts.RequestTenant(ctx, r)
	if err != nil {
		return nil, err
	}
	if publicRoute && (group == "auth" || tenantBoundPublicMethods.Has(path)) {
		var nested *core.Object
		if path == "auth/confirmMfa" {
			if object, isObject := body.Get("credential").(*core.Object); isObject && object != nil {
				nested = object
			}
		}
		holders := []*core.Object{body}
		if nested != nil {
			holders = append(holders, nested)
		}
		for _, holder := range holders {
			if holder == body && nested != nil && isUndefined(body.Get("tenantId")) {
				continue
			}
			if pinned != nil {
				if isUndefined(holder.Get("tenantId")) {
					holder.Set("tenantId", pinned.TenantID)
				} else if holder.Get("tenantId") != pinned.TenantID {
					return nil, core.NewIamError("HOST_MISMATCH", "This address belongs to another organization", 403)
				}
			} else if tenantID, isString := holder.Get("tenantId").(string); isString {
				if err := server.Hosts.AssertTenantServedHere(ctx, tenantID); err != nil {
					return nil, err
				}
			}
		}
	}
	tenantID, _ := body.Get("tenantId").(string)
	// A bearer credential takes precedence over the cookie, so a bearer-authenticated request neither replaces nor
	// clears the browser's session cookie. Public routes use no request credential.
	authorization, _ := headerValue(r.Header, "authorization")
	bearer := !publicRoute && authorization != ""
	var code string
	extra := (*SpanExtra)(nil)
	if requestID != "" {
		extra = &SpanExtra{RequestID: requestID}
	}
	return Span(server.Observe, "http", h.routeName(path), tenantID, func() (*Response, error) {
		response, err := h.call(ctx, r, path, body, bearer, client, origin, pinned)
		if err != nil {
			var known *core.IamError
			if errors.As(err, &known) {
				code = known.Code
			} else {
				code = "INTERNAL_ERROR"
			}
			response = errorResponse(err)
			// Signing out forgets the browser's cookie even when the sign-out is refused.
			if path == "auth/signOut" && !bearer {
				zero := 0.0
				response.Header.Add("Set-Cookie", h.cookie("", &zero))
			}
		}
		return answerWith(response, answerHeaders), nil
	}, func(response *Response) SpanResult {
		outcome := "error"
		if response.ok() {
			outcome = "ok"
		} else if DeniedStatuses[response.Status] {
			outcome = "denied"
		}
		return SpanResult{Status: response.Status, Outcome: outcome, Code: code}
	}, extra)
}

// call dispatches an RPC request and builds its answer with the cookie rules.
func (h *HTTPTransport) call(ctx context.Context, r *http.Request, path string, body *core.Object, bearer bool, client *core.SessionClientInfo, origin string, pinned *HostMatch) (*Response, error) {
	server := h.server
	if deviceTokenRoutes.Has(path) && isUndefined(body.Get("deviceToken")) {
		if remembered, found := h.deviceCookieValue(r.Header); found && remembered != "" {
			decoded, err := decodeURIComponent(remembered)
			if err != nil {
				return nil, err
			}
			body.Set("deviceToken", decoded)
		}
	}
	host := &auth.RequestHost{Origin: origin}
	if pinned != nil {
		host.TenantID = pinned.TenantID
	}
	scoped := server.Auth.WithRequestHost(server.Auth.WithClient(ctx, client), host)
	result, err := h.dispatch(scoped, path, body, core.CredentialInput{Headers: r.Header})
	if err != nil {
		return nil, err
	}
	model, err := ToModel(result)
	if err != nil {
		return nil, err
	}
	headers := hardened()
	if object, isObject := model.(*core.Object); isObject && object != nil {
		if !bearer && sessionCookieRoutes.Has(path) && object.Has("token") && object.Has("session") {
			headers.Add("Set-Cookie", h.sessionCookie(object.Get("token"), member(object.Get("session"), "expiresAt"), h.persistentFor(r.Header)))
		}
		if deviceToken, isString := object.Get("deviceToken").(string); isString {
			if expiresAt, isNumber := object.Get("deviceExpiresAt").(float64); isNumber {
				headers.Add("Set-Cookie", h.deviceCookieFor(deviceToken, expiresAt))
			}
		}
	}
	if path == "auth/signOut" && !bearer {
		zero := 0.0
		headers.Set("Set-Cookie", h.cookie("", &zero))
	}
	if path == "auth/revokeTrustedDevices" {
		zero := 0.0
		headers.Add("Set-Cookie", h.cookieNamed("better-iam.device", "", &zero))
	}
	return jsonResponse(core.NewObject("data", publicResult(model)), 200, headers), nil
}

// ServeHTTP is the Node transport (TypeScript `nodeHandler`): node-style protocol mounts first, then the body read
// under its limit (64 KiB under the base path, 2 MiB elsewhere) and the fetch-style handler.
func (h *HTTPTransport) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	failed := func(err error) {
		var known *core.IamError
		status, code, message := 500, "INTERNAL_ERROR", "Internal server error"
		if errors.As(err, &known) {
			status, code, message = known.Status, known.Code, known.Message
		}
		text, _, _ := core.Stringify(core.NewObject("error", core.NewObject("code", code, "message", message)))
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, text)
	}
	switch req.Method {
	case "TRACE", "CONNECT", "TRACK":
		failed(core.NewIamError("METHOD_NOT_ALLOWED", "Method is not supported", 405))
		return
	}
	target, err := h.requestURL(req)
	if err != nil {
		failed(core.NewIamError("INVALID_REQUEST", "Invalid request target", 400))
		return
	}
	request := req.Clone(req.Context())
	request.URL = target
	request.Host = target.Host
	client := (*core.SessionClientInfo)(nil)
	for _, protocol := range h.server.MountedProtocols {
		if protocol.Node {
			client = ClientFromRequest(h.server.Options, request)
			break
		}
	}
	nodeCtx := h.server.Auth.WithClient(req.Context(), client)
	for _, protocol := range h.server.MountedProtocols {
		if protocol.Handle == nil || !protocol.Node {
			continue
		}
		if protocol.Handle(w, request.WithContext(nodeCtx)) {
			return
		}
	}
	maxBody := int64(2097152)
	if strings.HasPrefix(target.EscapedPath(), h.server.Config.BasePath+"/") {
		maxBody = 65536
	}
	var body []byte
	hasBody := req.Method != http.MethodGet && req.Method != http.MethodHead
	if hasBody && req.Body != nil {
		data, err := io.ReadAll(io.LimitReader(req.Body, maxBody+1))
		if err != nil {
			failed(err)
			return
		}
		if int64(len(data)) > maxBody {
			w.WriteHeader(413)
			_, _ = io.WriteString(w, "Request too large")
			return
		}
		body = data
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	response := h.handle(request, body, hasBody)
	writeResponse(w, response)
}

// requestURL is the URL the Node transport resolves a request to: the deployment's base URL, or with organization
// addresses the host the request was sent to.
func (h *HTTPTransport) requestURL(req *http.Request) (*url.URL, error) {
	base := h.server.Config.BaseURL
	scheme := strings.TrimSuffix(base.Protocol, ":")
	host := urlHost(base)
	if h.server.Hosts.Enabled {
		if normalized := NormalizeHost(req.Host); normalized != "" {
			host = normalized
		}
	}
	raw := req.RequestURI
	if raw == "" {
		raw = req.URL.RequestURI()
	}
	if !strings.HasPrefix(raw, "/") {
		parsed, err := url.Parse(raw)
		if err != nil {
			return nil, err
		}
		raw = parsed.RequestURI()
	}
	return url.Parse(scheme + "://" + host + raw)
}

// urlHost is URL#host: the hostname and, unless it is the scheme's default, the port.
func urlHost(u *auth.FetchURL) string {
	if u.Port != "" {
		return u.Hostname + ":" + u.Port
	}
	return u.Hostname
}

// writeResponse writes a Response to a ResponseWriter.
func writeResponse(w http.ResponseWriter, response *Response) {
	header := w.Header()
	keys := make([]string, 0, len(response.Header))
	for key := range response.Header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		header[key] = append([]string(nil), response.Header[key]...)
	}
	w.WriteHeader(response.Status)
	if len(response.Body) > 0 {
		_, _ = w.Write(response.Body)
	}
}

// UseProtocol mounts a protocol service under its base path for both transports.
func (h *HTTPTransport) UseProtocol(protocol ProtocolService) {
	path := strings.TrimSuffix(protocol.BasePath, "/")
	if protocol.Handler != nil {
		h.server.MountedProtocols = append(h.server.MountedProtocols, ProtocolMount{Handle: protocol.Handler})
	}
	if protocol.NodeHandler != nil {
		handler := protocol.NodeHandler
		h.server.MountedProtocols = append(h.server.MountedProtocols, ProtocolMount{Node: true, Handle: func(w http.ResponseWriter, r *http.Request) bool {
			pathname := r.URL.EscapedPath()
			if pathname != path && !strings.HasPrefix(pathname, path+"/") && pathname != "/.well-known/oauth-authorization-server"+path {
				return false
			}
			handler.ServeHTTP(w, r)
			return true
		}})
	}
}

// --- the authentication API group ----------------------------------------------------------------------------------

// AuthAPI is the authentication group (createAuthApi): each method is timed as an `auth` span named after the
// method, and a call outside the HTTP handler whose credential carries the request's headers runs with the client
// derived from them.
type AuthAPI struct {
	auth     *auth.Service
	observe  *Observer
	clientOf func(headers http.Header) *core.SessionClientInfo
}

// CreateAuthAPI builds the group; clientOf (nil: none) derives the client of in-process calls from their headers.
func CreateAuthAPI(service *auth.Service, observe *Observer, clientOf func(headers http.Header) *core.SessionClientInfo) *AuthAPI {
	return &AuthAPI{auth: service, observe: observe, clientOf: clientOf}
}

// anyResult turns a typed result into (any, error) without a typed nil.
func anyResult[T any](value T, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	return value, nil
}

// authHeadersOf are the request headers a call carries: the credential itself, or an MFA enrollment's credential,
// or a public body's `headers` member.
func authHeadersOf(first any) http.Header {
	switch value := first.(type) {
	case core.CredentialInput:
		return value.Headers
	case auth.MfaCredential:
		if value.Credentials != nil {
			return value.Credentials.Headers
		}
	case auth.ConfirmMfaInput:
		if value.Credential.Credentials != nil {
			return value.Credential.Credentials.Headers
		}
	case *core.Object:
		if value == nil {
			return nil
		}
		if headers, isObject := value.Get("headers").(*core.Object); isObject && headers != nil {
			header := http.Header{}
			for _, key := range headers.Keys() {
				header.Add(key, jsString(headers.Get(key)))
			}
			return header
		}
	}
	return nil
}

func authTenantOf(first any) string {
	switch value := first.(type) {
	case *core.Object:
		if value != nil {
			tenantID, _ := value.Get("tenantId").(string)
			return tenantID
		}
	case auth.MfaCredential:
		if value.Credentials == nil {
			return value.TenantID
		}
	}
	return ""
}

func authCall[T any](ctx context.Context, a *AuthAPI, name string, first any, fn func(ctx context.Context) (any, error)) (Out[T], error) {
	if a.clientOf != nil && a.auth.CurrentClient(ctx) == nil {
		if headers := authHeadersOf(first); headers != nil {
			ctx = a.auth.WithClient(ctx, a.clientOf(headers))
		}
	}
	value, err := Span(a.observe, "auth", name, authTenantOf(first), func() (any, error) { return fn(ctx) }, nil, nil)
	return Out[T]{Value: value}, err
}

// --- URI components ------------------------------------------------------------------------------------------------

const uriUnreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()"

// encodeURIComponent is the JavaScript global; unpaired surrogates (a URIError there) are encoded as U+FFFD.
func encodeURIComponent(s string) string {
	var b strings.Builder
	for _, c := range utf8Bytes(s) {
		if strings.IndexByte(uriUnreserved, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteString("%" + strings.ToUpper(strconv.FormatUint(uint64(c)|0x100, 16)[1:]))
	}
	return b.String()
}

// uriError is a JavaScript URIError (a 500 when it escapes a request).
type uriError struct{}

func (uriError) Error() string { return "URI malformed" }

// Name is the JavaScript error name.
func (uriError) Name() string { return "URIError" }

// decodeURIComponent is the JavaScript global: malformed escapes and invalid UTF-8 are a URIError.
func decodeURIComponent(s string) (string, error) {
	if !strings.Contains(s, "%") {
		return s, nil
	}
	var out []byte
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			out = append(out, s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", uriError{}
		}
		value, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
		if err != nil {
			return "", uriError{}
		}
		out = append(out, byte(value))
		i += 2
	}
	if !utf8.Valid(out) {
		return "", uriError{}
	}
	return string(out), nil
}

// BeginMfa is POST {basePath}/auth/beginMfa: starts authenticator enrollment with a sign-in challenge or the request's own credential.
func (a *AuthAPI) BeginMfa(ctx context.Context, credential auth.MfaCredential) (Out[apitypes.AuthBeginMfaOutput], error) {
	first := any(credential)
	if credential.Credentials != nil {
		first = *credential.Credentials
	}
	return authCall[apitypes.AuthBeginMfaOutput](ctx, a, "beginMfa", first, func(ctx context.Context) (any, error) { return anyResult(a.auth.BeginMfa(ctx, credential)) })
}

// BeginPasskeyAuthentication is POST {basePath}/auth/beginPasskeyAuthentication (public).
func (a *AuthAPI) BeginPasskeyAuthentication(ctx context.Context, input In[apitypes.AuthBeginPasskeyAuthenticationInput]) (Out[apitypes.AuthBeginPasskeyAuthenticationOutput], error) {
	return authCall[apitypes.AuthBeginPasskeyAuthenticationOutput](ctx, a, "beginPasskeyAuthentication", input.Body, func(ctx context.Context) (any, error) {
		return anyResult(a.auth.BeginPasskeyAuthentication(ctx, input.Body))
	})
}

// BeginPasskeyMfa is POST {basePath}/auth/beginPasskeyMfa (public).
func (a *AuthAPI) BeginPasskeyMfa(ctx context.Context, input In[apitypes.AuthBeginPasskeyMfaInput]) (Out[apitypes.AuthBeginPasskeyMfaOutput], error) {
	return authCall[apitypes.AuthBeginPasskeyMfaOutput](ctx, a, "beginPasskeyMfa", input.Body, func(ctx context.Context) (any, error) { return anyResult(a.auth.BeginPasskeyMfa(ctx, input.Body)) })
}

// BeginPasskeyRegistration is POST {basePath}/auth/beginPasskeyRegistration.
func (a *AuthAPI) BeginPasskeyRegistration(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthBeginPasskeyRegistrationInput]) (Out[apitypes.AuthBeginPasskeyRegistrationOutput], error) {
	return authCall[apitypes.AuthBeginPasskeyRegistrationOutput](ctx, a, "beginPasskeyRegistration", credential, func(ctx context.Context) (any, error) {
		return anyResult(a.auth.BeginPasskeyRegistration(ctx, credential))
	})
}

// ChangePassword is POST {basePath}/auth/changePassword.
func (a *AuthAPI) ChangePassword(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthChangePasswordInput]) (Out[apitypes.AuthChangePasswordOutput], error) {
	return authCall[apitypes.AuthChangePasswordOutput](ctx, a, "changePassword", credential, func(ctx context.Context) (any, error) {
		return anyResult(a.auth.ChangePassword(ctx, credential, input.Body))
	})
}

// ConfirmEmailChange is POST {basePath}/auth/confirmEmailChange (public).
func (a *AuthAPI) ConfirmEmailChange(ctx context.Context, input In[apitypes.AuthConfirmEmailChangeInput]) (Out[apitypes.AuthConfirmEmailChangeOutput], error) {
	return authCall[apitypes.AuthConfirmEmailChangeOutput](ctx, a, "confirmEmailChange", input.Body, func(ctx context.Context) (any, error) { return anyResult(a.auth.ConfirmEmailChange(ctx, input.Body)) })
}

// ConfirmMfa is POST {basePath}/auth/confirmMfa: confirms enrollment with the first code.
func (a *AuthAPI) ConfirmMfa(ctx context.Context, input auth.ConfirmMfaInput) (Out[apitypes.AuthConfirmMfaOutput], error) {
	return authCall[apitypes.AuthConfirmMfaOutput](ctx, a, "confirmMfa", input, func(ctx context.Context) (any, error) { return anyResult(a.auth.ConfirmMfa(ctx, input)) })
}

// ConfirmPhoneVerification is POST {basePath}/auth/confirmPhoneVerification.
func (a *AuthAPI) ConfirmPhoneVerification(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthConfirmPhoneVerificationInput]) (Out[apitypes.AuthConfirmPhoneVerificationOutput], error) {
	return authCall[apitypes.AuthConfirmPhoneVerificationOutput](ctx, a, "confirmPhoneVerification", credential, func(ctx context.Context) (any, error) {
		return anyResult(a.auth.ConfirmPhoneVerification(ctx, credential, input.Body))
	})
}

// DeletePasskey is POST {basePath}/auth/deletePasskey.
func (a *AuthAPI) DeletePasskey(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthDeletePasskeyInput]) (Out[apitypes.AuthDeletePasskeyOutput], error) {
	return authCall[apitypes.AuthDeletePasskeyOutput](ctx, a, "deletePasskey", credential, func(ctx context.Context) (any, error) {
		return anyResult(a.auth.DeletePasskey(ctx, credential, input.Body))
	})
}

// DisableMfa is POST {basePath}/auth/disableMfa.
func (a *AuthAPI) DisableMfa(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthDisableMfaInput]) (Out[apitypes.AuthDisableMfaOutput], error) {
	return authCall[apitypes.AuthDisableMfaOutput](ctx, a, "disableMfa", credential, func(ctx context.Context) (any, error) { return anyResult(a.auth.DisableMfa(ctx, credential)) })
}

// FinishPasskeyAuthentication is POST {basePath}/auth/finishPasskeyAuthentication (public).
func (a *AuthAPI) FinishPasskeyAuthentication(ctx context.Context, input In[apitypes.AuthFinishPasskeyAuthenticationInput]) (Out[apitypes.AuthFinishPasskeyAuthenticationOutput], error) {
	return authCall[apitypes.AuthFinishPasskeyAuthenticationOutput](ctx, a, "finishPasskeyAuthentication", input.Body, func(ctx context.Context) (any, error) {
		return anyResult(a.auth.FinishPasskeyAuthentication(ctx, input.Body))
	})
}

// FinishPasskeyMfa is POST {basePath}/auth/finishPasskeyMfa (public).
func (a *AuthAPI) FinishPasskeyMfa(ctx context.Context, input In[apitypes.AuthFinishPasskeyMfaInput]) (Out[apitypes.AuthFinishPasskeyMfaOutput], error) {
	return authCall[apitypes.AuthFinishPasskeyMfaOutput](ctx, a, "finishPasskeyMfa", input.Body, func(ctx context.Context) (any, error) { return anyResult(a.auth.FinishPasskeyMfa(ctx, input.Body)) })
}

// FinishPasskeyRegistration is POST {basePath}/auth/finishPasskeyRegistration.
func (a *AuthAPI) FinishPasskeyRegistration(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthFinishPasskeyRegistrationInput]) (Out[apitypes.AuthFinishPasskeyRegistrationOutput], error) {
	return authCall[apitypes.AuthFinishPasskeyRegistrationOutput](ctx, a, "finishPasskeyRegistration", credential, func(ctx context.Context) (any, error) {
		return anyResult(a.auth.FinishPasskeyRegistration(ctx, credential, input.Body))
	})
}

// FinishPasswordless is POST {basePath}/auth/finishPasswordless (public).
func (a *AuthAPI) FinishPasswordless(ctx context.Context, input In[apitypes.AuthFinishPasswordlessInput]) (Out[apitypes.AuthFinishPasswordlessOutput], error) {
	return authCall[apitypes.AuthFinishPasswordlessOutput](ctx, a, "finishPasswordless", input.Body, func(ctx context.Context) (any, error) { return anyResult(a.auth.FinishPasswordless(ctx, input.Body)) })
}

// GetSession is POST {basePath}/auth/getSession.
func (a *AuthAPI) GetSession(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthGetSessionInput]) (Out[apitypes.AuthGetSessionOutput], error) {
	return authCall[apitypes.AuthGetSessionOutput](ctx, a, "getSession", credential, func(ctx context.Context) (any, error) { return anyResult(a.auth.GetSession(ctx, credential)) })
}

// ListPasskeys is POST {basePath}/auth/listPasskeys.
func (a *AuthAPI) ListPasskeys(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthListPasskeysInput]) (Out[apitypes.AuthListPasskeysOutput], error) {
	return authCall[apitypes.AuthListPasskeysOutput](ctx, a, "listPasskeys", credential, func(ctx context.Context) (any, error) { return anyResult(a.auth.ListPasskeys(ctx, credential)) })
}

// ListSecurityEvents is POST {basePath}/auth/listSecurityEvents.
func (a *AuthAPI) ListSecurityEvents(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthListSecurityEventsInput]) (Out[apitypes.AuthListSecurityEventsOutput], error) {
	return authCall[apitypes.AuthListSecurityEventsOutput](ctx, a, "listSecurityEvents", credential, func(ctx context.Context) (any, error) {
		return anyResult(a.auth.ListSecurityEvents(ctx, credential, input.Body))
	})
}

// ListSessions is POST {basePath}/auth/listSessions.
func (a *AuthAPI) ListSessions(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthListSessionsInput]) (Out[apitypes.AuthListSessionsOutput], error) {
	return authCall[apitypes.AuthListSessionsOutput](ctx, a, "listSessions", credential, func(ctx context.Context) (any, error) { return anyResult(a.auth.ListSessions(ctx, credential)) })
}

// ListTrustedDevices is POST {basePath}/auth/listTrustedDevices.
func (a *AuthAPI) ListTrustedDevices(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthListTrustedDevicesInput]) (Out[apitypes.AuthListTrustedDevicesOutput], error) {
	return authCall[apitypes.AuthListTrustedDevicesOutput](ctx, a, "listTrustedDevices", credential, func(ctx context.Context) (any, error) { return anyResult(a.auth.ListTrustedDevices(ctx, credential)) })
}

// MfaStatus is POST {basePath}/auth/mfaStatus.
func (a *AuthAPI) MfaStatus(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthMfaStatusInput]) (Out[apitypes.AuthMfaStatusOutput], error) {
	return authCall[apitypes.AuthMfaStatusOutput](ctx, a, "mfaStatus", credential, func(ctx context.Context) (any, error) { return anyResult(a.auth.MfaStatus(ctx, credential)) })
}

// Reauthenticate is POST {basePath}/auth/reauthenticate.
func (a *AuthAPI) Reauthenticate(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthReauthenticateInput]) (Out[apitypes.AuthReauthenticateOutput], error) {
	return authCall[apitypes.AuthReauthenticateOutput](ctx, a, "reauthenticate", credential, func(ctx context.Context) (any, error) {
		return anyResult(a.auth.Reauthenticate(ctx, credential, input.Body))
	})
}

// RecoverMfa is POST {basePath}/auth/recoverMfa (public).
func (a *AuthAPI) RecoverMfa(ctx context.Context, input In[apitypes.AuthRecoverMfaInput]) (Out[apitypes.AuthRecoverMfaOutput], error) {
	return authCall[apitypes.AuthRecoverMfaOutput](ctx, a, "recoverMfa", input.Body, func(ctx context.Context) (any, error) { return anyResult(a.auth.RecoverMfa(ctx, input.Body)) })
}

// RegenerateRecoveryCodes is POST {basePath}/auth/regenerateRecoveryCodes.
func (a *AuthAPI) RegenerateRecoveryCodes(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthRegenerateRecoveryCodesInput]) (Out[apitypes.AuthRegenerateRecoveryCodesOutput], error) {
	return authCall[apitypes.AuthRegenerateRecoveryCodesOutput](ctx, a, "regenerateRecoveryCodes", credential, func(ctx context.Context) (any, error) {
		return anyResult(a.auth.RegenerateRecoveryCodes(ctx, credential))
	})
}

// RenamePasskey is POST {basePath}/auth/renamePasskey.
func (a *AuthAPI) RenamePasskey(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthRenamePasskeyInput]) (Out[apitypes.AuthRenamePasskeyOutput], error) {
	return authCall[apitypes.AuthRenamePasskeyOutput](ctx, a, "renamePasskey", credential, func(ctx context.Context) (any, error) {
		return anyResult(a.auth.RenamePasskey(ctx, credential, input.Body))
	})
}

// RequestEmailChange is POST {basePath}/auth/requestEmailChange.
func (a *AuthAPI) RequestEmailChange(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthRequestEmailChangeInput]) (Out[apitypes.AuthRequestEmailChangeOutput], error) {
	return authCall[apitypes.AuthRequestEmailChangeOutput](ctx, a, "requestEmailChange", credential, func(ctx context.Context) (any, error) {
		return anyResult(a.auth.RequestEmailChange(ctx, credential, input.Body))
	})
}

// RequestEmailVerification is POST {basePath}/auth/requestEmailVerification (public).
func (a *AuthAPI) RequestEmailVerification(ctx context.Context, input In[apitypes.AuthRequestEmailVerificationInput]) (Out[apitypes.AuthRequestEmailVerificationOutput], error) {
	return authCall[apitypes.AuthRequestEmailVerificationOutput](ctx, a, "requestEmailVerification", input.Body, func(ctx context.Context) (any, error) {
		return anyResult(a.auth.RequestEmailVerification(ctx, input.Body))
	})
}

// RequestMfaCode is POST {basePath}/auth/requestMfaCode (public).
func (a *AuthAPI) RequestMfaCode(ctx context.Context, input In[apitypes.AuthRequestMfaCodeInput]) (Out[apitypes.AuthRequestMfaCodeOutput], error) {
	return authCall[apitypes.AuthRequestMfaCodeOutput](ctx, a, "requestMfaCode", input.Body, func(ctx context.Context) (any, error) { return anyResult(a.auth.RequestMfaCode(ctx, input.Body)) })
}

// RequestPasswordReset is POST {basePath}/auth/requestPasswordReset (public).
func (a *AuthAPI) RequestPasswordReset(ctx context.Context, input In[apitypes.AuthRequestPasswordResetInput]) (Out[apitypes.AuthRequestPasswordResetOutput], error) {
	return authCall[apitypes.AuthRequestPasswordResetOutput](ctx, a, "requestPasswordReset", input.Body, func(ctx context.Context) (any, error) { return anyResult(a.auth.RequestPasswordReset(ctx, input.Body)) })
}

// ResetPassword is POST {basePath}/auth/resetPassword (public).
func (a *AuthAPI) ResetPassword(ctx context.Context, input In[apitypes.AuthResetPasswordInput]) (Out[apitypes.AuthResetPasswordOutput], error) {
	return authCall[apitypes.AuthResetPasswordOutput](ctx, a, "resetPassword", input.Body, func(ctx context.Context) (any, error) { return anyResult(a.auth.ResetPassword(ctx, input.Body)) })
}

// RevokeOtherSessions is POST {basePath}/auth/revokeOtherSessions.
func (a *AuthAPI) RevokeOtherSessions(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthRevokeOtherSessionsInput]) (Out[apitypes.AuthRevokeOtherSessionsOutput], error) {
	return authCall[apitypes.AuthRevokeOtherSessionsOutput](ctx, a, "revokeOtherSessions", credential, func(ctx context.Context) (any, error) { return anyResult(a.auth.RevokeOtherSessions(ctx, credential)) })
}

// RevokeSession is POST {basePath}/auth/revokeSession.
func (a *AuthAPI) RevokeSession(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthRevokeSessionInput]) (Out[apitypes.AuthRevokeSessionOutput], error) {
	return authCall[apitypes.AuthRevokeSessionOutput](ctx, a, "revokeSession", credential, func(ctx context.Context) (any, error) {
		return anyResult(a.auth.RevokeSession(ctx, credential, input.Body))
	})
}

// RevokeTrustedDevice is POST {basePath}/auth/revokeTrustedDevice.
func (a *AuthAPI) RevokeTrustedDevice(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthRevokeTrustedDeviceInput]) (Out[apitypes.AuthRevokeTrustedDeviceOutput], error) {
	return authCall[apitypes.AuthRevokeTrustedDeviceOutput](ctx, a, "revokeTrustedDevice", credential, func(ctx context.Context) (any, error) {
		return anyResult(a.auth.RevokeTrustedDevice(ctx, credential, input.Body))
	})
}

// RevokeTrustedDevices is POST {basePath}/auth/revokeTrustedDevices.
func (a *AuthAPI) RevokeTrustedDevices(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthRevokeTrustedDevicesInput]) (Out[apitypes.AuthRevokeTrustedDevicesOutput], error) {
	return authCall[apitypes.AuthRevokeTrustedDevicesOutput](ctx, a, "revokeTrustedDevices", credential, func(ctx context.Context) (any, error) { return anyResult(a.auth.RevokeTrustedDevices(ctx, credential)) })
}

// SignIn is POST {basePath}/auth/signIn (public).
func (a *AuthAPI) SignIn(ctx context.Context, input In[apitypes.AuthSignInInput]) (Out[apitypes.AuthSignInOutput], error) {
	return authCall[apitypes.AuthSignInOutput](ctx, a, "signIn", input.Body, func(ctx context.Context) (any, error) { return anyResult(a.auth.SignIn(ctx, input.Body)) })
}

// SignOut is POST {basePath}/auth/signOut.
func (a *AuthAPI) SignOut(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthSignOutInput]) (Out[apitypes.AuthSignOutOutput], error) {
	return authCall[apitypes.AuthSignOutOutput](ctx, a, "signOut", credential, func(ctx context.Context) (any, error) { return anyResult(a.auth.SignOut(ctx, credential)) })
}

// SignUp is POST {basePath}/auth/signUp (public).
func (a *AuthAPI) SignUp(ctx context.Context, input In[apitypes.AuthSignUpInput]) (Out[apitypes.AuthSignUpOutput], error) {
	return authCall[apitypes.AuthSignUpOutput](ctx, a, "signUp", input.Body, func(ctx context.Context) (any, error) { return anyResult(a.auth.SignUp(ctx, input.Body)) })
}

// StartPasswordless is POST {basePath}/auth/startPasswordless (public).
func (a *AuthAPI) StartPasswordless(ctx context.Context, input In[apitypes.AuthStartPasswordlessInput]) (Out[apitypes.AuthStartPasswordlessOutput], error) {
	return authCall[apitypes.AuthStartPasswordlessOutput](ctx, a, "startPasswordless", input.Body, func(ctx context.Context) (any, error) { return anyResult(a.auth.StartPasswordless(ctx, input.Body)) })
}

// StartPhoneVerification is POST {basePath}/auth/startPhoneVerification.
func (a *AuthAPI) StartPhoneVerification(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthStartPhoneVerificationInput]) (Out[apitypes.AuthStartPhoneVerificationOutput], error) {
	return authCall[apitypes.AuthStartPhoneVerificationOutput](ctx, a, "startPhoneVerification", credential, func(ctx context.Context) (any, error) {
		return anyResult(a.auth.StartPhoneVerification(ctx, credential, input.Body))
	})
}

// VerifyEmail is POST {basePath}/auth/verifyEmail (public).
func (a *AuthAPI) VerifyEmail(ctx context.Context, input In[apitypes.AuthVerifyEmailInput]) (Out[apitypes.AuthVerifyEmailOutput], error) {
	return authCall[apitypes.AuthVerifyEmailOutput](ctx, a, "verifyEmail", input.Body, func(ctx context.Context) (any, error) { return anyResult(a.auth.VerifyEmail(ctx, input.Body)) })
}

// VerifyMfa is POST {basePath}/auth/verifyMfa (public).
func (a *AuthAPI) VerifyMfa(ctx context.Context, input In[apitypes.AuthVerifyMfaInput]) (Out[apitypes.AuthVerifyMfaOutput], error) {
	return authCall[apitypes.AuthVerifyMfaOutput](ctx, a, "verifyMfa", input.Body, func(ctx context.Context) (any, error) { return anyResult(a.auth.VerifyMfa(ctx, input.Body)) })
}
