package cli

// Port of packages/cli/src/transport.ts.

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/Better-IAM/better-iam/go/client"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

// ApiTransport calls the IAM HTTP API surface by route (roles/create, auth/getSession, authorize): in process
// against a configured instance, or over HTTPS against a running server. Both expose exactly the routes the HTTP
// handler serves, with the same credential rules, so a command behaves the same locally and remotely.
type ApiTransport interface {
	// Mode is "local" or "remote".
	Mode() string
	// Target is the configuration file or endpoint URL the calls go to, for messages.
	Target() string
	// Call posts input (nil: {}) to a route and returns the answer as a JSON value (*core.Object, []any, string,
	// float64, bool or nil).
	Call(ctx context.Context, path string, input *core.Object) (any, error)
}

var (
	routeSegmentPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)
	topLevelRoutes      = map[string]bool{"authorize": true, "authorizeMany": true, "listAccessible": true}
)

// routePath splits roles.create, roles/create, or plugins/reports/summary into a route path; refuses anything else.
func routePath(route string) (string, error) {
	path := route
	if !strings.Contains(route, "/") {
		path = strings.Replace(route, ".", "/", 1)
	}
	parts := strings.Split(path, "/")
	valid := true
	for _, part := range parts {
		if !routeSegmentPattern.MatchString(part) {
			valid = false
		}
	}
	if !valid || (len(parts) > 2 && parts[0] != "plugins") {
		return "", UsageError(route + " is not an API route like roles.create or auth.getSession")
	}
	if len(parts) == 1 && !topLevelRoutes[path] {
		return "", UsageError(route + " names no method; use group.method (for example roles.list), or api --list " + route)
	}
	return path, nil
}

// isPublicRoute reports whether a route needs no credential over HTTP (sign-in ceremonies, invitation acceptance,
// discovery).
func isPublicRoute(path string) bool { return server.IsPublicRoute(path) }

type localTransport struct {
	iam        *server.BetterIam
	target     string
	credential core.CredentialInput
}

func (t *localTransport) Mode() string   { return "local" }
func (t *localTransport) Target() string { return t.target }

func (t *localTransport) Call(ctx context.Context, path string, input *core.Object) (any, error) {
	if input == nil {
		input = core.NewObject()
	}
	result, err := t.iam.DispatchRoute(ctx, t.credential, path, input)
	if err != nil {
		return nil, err
	}
	// Results as the HTTP API returns them: JSON values only (no undefined, dates as strings).
	converted := jsonValue(result)
	if core.IsUndefined(converted) {
		return nil, nil
	}
	return converted, nil
}

// LocalTransport calls API routes in process on a configured instance, as token (or with no credential when ""),
// exposing exactly the routes and credential rules of the HTTP handler; what token commands use without --url.
// There is no request-size limit here, unlike HTTP's 64 KiB, so large configuration files apply locally in one call.
func LocalTransport(iam *server.BetterIam, target, token string) ApiTransport {
	credential := core.CredentialInput{}
	if token != "" {
		credential.Token = token
	}
	return &localTransport{iam: iam, target: target, credential: credential}
}

// endpoint is a parsed --url: its origin, base path, and the two joined.
type endpoint struct {
	origin   string
	basePath string
	url      string
}

// parseEndpoint reads https://iam.example.com (default base path /api/iam) or the full endpoint
// https://host/custom/iam.
func parseEndpoint(raw string) (endpoint, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" {
		return endpoint{}, UsageError("--url " + raw + " is not an absolute http(s) URL")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if (scheme == "http" || scheme == "https") && (parsed.Opaque != "" || parsed.Hostname() == "") {
		return endpoint{}, UsageError("--url " + raw + " is not an absolute http(s) URL")
	}
	if (scheme != "http" && scheme != "https") || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || strings.Contains(raw, "#") {
		return endpoint{}, UsageError("--url must be an http(s) URL without credentials, query, or fragment")
	}
	hostname := strings.ToLower(parsed.Hostname())
	host := hostname
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := parsed.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	origin := scheme + "://" + host
	if port != "" {
		origin += ":" + port
	}
	// Passwords and bearer tokens never travel in clear text; the server itself requires HTTPS outside localhost too.
	if scheme == "http" && host != "localhost" && host != "127.0.0.1" && host != "[::1]" && !strings.HasSuffix(host, ".localhost") {
		return endpoint{}, UsageError("--url " + origin + " must use https (plain http is allowed for localhost only)")
	}
	path := parsed.EscapedPath()
	path = strings.TrimRight(path, "/")
	basePath := path
	if basePath == "" {
		basePath = "/api/iam"
	}
	return endpoint{origin: origin, basePath: basePath, url: origin + basePath}, nil
}

// sameEndpoint reports whether two endpoint URLs name the same IAM API (origin and base path), however they were
// written.
func sameEndpoint(a, b string) bool {
	left, err := parseEndpoint(a)
	if err != nil {
		return false
	}
	right, err := parseEndpoint(b)
	if err != nil {
		return false
	}
	return left.url == right.url
}

type remoteTransport struct {
	client *client.Client
	target string
}

func (t *remoteTransport) Mode() string   { return "remote" }
func (t *remoteTransport) Target() string { return t.target }

func (t *remoteTransport) Call(ctx context.Context, path string, input *core.Object) (any, error) {
	if input == nil {
		input = core.NewObject()
	}
	result, err := t.client.Request(ctx, path, input)
	if err != nil {
		return nil, err
	}
	converted := jsonValue(result)
	if core.IsUndefined(converted) {
		return nil, nil
	}
	return converted, nil
}

// RemoteTransport calls API routes on a running IAM server over HTTP(S) with a bearer token, through the typed
// client (request IDs, one retry after a short rate limit); what token commands use with --url or a profile saved
// against a server. fetch replaces the HTTP client (tests, custom transports).
func RemoteTransport(rawURL, token string, fetch func(*http.Request) (*http.Response, error)) (ApiTransport, error) {
	parsed, err := parseEndpoint(rawURL)
	if err != nil {
		return nil, err
	}
	host, _ := url.Parse(parsed.origin)
	// Plain http is allowed for *.localhost names only because they mean this machine, but they resolve through the
	// system resolver, which may answer anything: check that the name really is loopback before a password or token
	// goes out in clear text.
	transport := fetch
	if fetch == nil && host.Scheme == "http" && strings.HasSuffix(host.Hostname(), ".localhost") {
		transport = loopbackOnly(host.Hostname())
	}
	options := client.Options{
		BaseURL:           parsed.origin,
		BasePath:          parsed.basePath,
		Token:             token,
		Fetch:             transport,
		GenerateRequestID: true,
		RetryRateLimited:  true,
	}
	c, err := client.New(options)
	if err != nil {
		return nil, err
	}
	return &remoteTransport{client: c, target: parsed.url}, nil
}

// loopbackOnly is the fetch of a plain-http *.localhost endpoint: refused unless every address the name resolves to
// is loopback.
func loopbackOnly(hostname string) func(*http.Request) (*http.Response, error) {
	return func(request *http.Request) (*http.Response, error) {
		addresses, _ := net.DefaultResolver.LookupHost(request.Context(), hostname)
		loopback := len(addresses) > 0
		for _, address := range addresses {
			if !strings.HasPrefix(address, "127.") && address != "::1" {
				loopback = false
			}
		}
		if !loopback {
			return nil, UsageError(hostname+" does not resolve to this machine, so it needs https", "Use http://localhost or https://.")
		}
		noRedirect := *http.DefaultClient
		noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return noRedirect.Do(request)
	}
}

// RouteInfo is one route of the HTTP API and whether it needs a credential ("public" or "token").
type RouteInfo = server.RouteAccess

// ListRoutes lists every route the HTTP API serves, with whether it needs a credential, sorted by route.
func ListRoutes() []RouteInfo {
	routes := server.Routes()
	sort.SliceStable(routes, func(i, j int) bool { return localeCompare(routes[i].Route, routes[j].Route) < 0 })
	return routes
}
