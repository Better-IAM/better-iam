package auth

// Port of packages/auth/src/safe-fetch.ts: guarded outbound HTTP for URLs that tenants control (OIDC discovery
// documents and JWKS, webhook endpoints, SCIM targets, Shared Signals receivers, AI provider base URLs). It refuses
// anything that could turn the server into a proxy into its own network (SSRF): non-public resolved addresses
// (checked at connect time, so DNS rebinding cannot swap in a private address after validation), redirects, plain
// http, non-443 https ports unless allowed, and credentials in the URL.

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Better-IAM/better-iam/go/core"
)

// SafeFetchOptions are the limits of FetchJSONSafely.
type SafeFetchOptions struct {
	// TimeoutMs is the deadline for the whole request.
	TimeoutMs int64
	// MaxBytes is the largest accepted response body.
	MaxBytes int64
	// AllowPrivateNetworks lets requests reach private and reserved addresses. Development and tests only.
	AllowPrivateNetworks bool
	// AllowInsecureLocalhost allows http:// and any port on loopback hosts (localhost, 127.0.0.1, [::1]).
	AllowInsecureLocalhost bool
}

// SafeFetchFailureReason says which rule stopped a guarded fetch: url, address, timeout, status, size,
// content-type, redirect, json or network.
type SafeFetchFailureReason = string

// SafeFetchError is a refused or failed guarded fetch.
type SafeFetchError struct {
	Reason  SafeFetchFailureReason
	Message string
}

func (e *SafeFetchError) Error() string { return e.Message }

// Name is the JavaScript error name.
func (e *SafeFetchError) Name() string { return "SafeFetchError" }

// NewSafeFetchError builds a SafeFetchError; the message defaults to "Fetch refused: <reason>".
func NewSafeFetchError(reason SafeFetchFailureReason, message ...string) *SafeFetchError {
	text := "Fetch refused: " + reason
	if len(message) > 0 {
		text = message[0]
	}
	return &SafeFetchError{Reason: reason, Message: text}
}

// nonPublicNetworks are never reachable through a guarded fetch: this-network, RFC 1918, CGNAT, loopback,
// link-local, IETF protocol assignments, documentation and benchmarking ranges, 6to4 relay, multicast and reserved
// space, and their IPv6 counterparts including IPv4-translated (::ffff:0:0:0/96), NAT64, discard-only,
// Teredo/ORCHID (2001::/23), 6to4, ULA and site-local. IPv4-mapped IPv6 addresses are judged by their IPv4 address.
var nonPublicNetworks = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
	"192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "::/96", "::ffff:0:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48",
	"100::/64", "2001::/23", "2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
}

var loopbackHosts = map[string]bool{"localhost": true, "127.0.0.1": true, "[::1]": true, "::1": true}

// IsPublicAddress is true for a globally routable unicast address; false for private, reserved and malformed
// values.
func IsPublicAddress(address string) bool {
	if _, ok := core.IPCounterKey(address); !ok {
		return false
	}
	trimmed := core.JSTrim(address)
	for _, network := range nonPublicNetworks {
		if core.IPMatches(trimmed, network) {
			return false
		}
	}
	return true
}

func isLoopbackAddress(address string) bool {
	return core.IPMatches(address, "127.0.0.0/8") || core.IPMatches(address, "::1/128")
}

// SafeFetchAddressOptions are the address rules of a guarded request.
type SafeFetchAddressOptions struct {
	AllowPrivateNetworks   bool
	AllowInsecureLocalhost bool
	// AnyPort also allows https on ports other than 443 (the address rules still apply).
	AnyPort bool
}

// FetchURL is a URL as the WHATWG URL parser reads it (the parts the guards use).
type FetchURL struct {
	*url.URL
	// Protocol is the lowercase scheme with a colon ("https:").
	Protocol string
	// Hostname is the WHATWG hostname: lowercase, IPv4 forms normalized, IPv6 in brackets.
	Hostname string
	// Port is "" for the scheme's default port.
	Port string
	// Href is the serialized URL.
	Href string
}

var specialPorts = map[string]string{"http": "80", "https": "443", "ws": "80", "wss": "443", "ftp": "21"}

// parseWHATWGIPv4 parses a host as the WHATWG IPv4 parser does; ok is false when the host is not an IPv4 address,
// err set when it ends in a number but is not a valid one.
func parseWHATWGIPv4(host string) (string, bool, error) {
	parts := strings.Split(host, ".")
	if len(parts) > 1 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	last := parts[len(parts)-1]
	endsInNumber := last != "" && strings.Trim(last, "0123456789") == ""
	if !endsInNumber && (strings.HasPrefix(last, "0x") || strings.HasPrefix(last, "0X")) {
		hexDigits := last[2:]
		endsInNumber = strings.Trim(hexDigits, "0123456789abcdefABCDEF") == ""
	}
	if !endsInNumber {
		return "", false, nil
	}
	invalid := errors.New("invalid IPv4 address")
	if len(parts) > 4 {
		return "", false, invalid
	}
	numbers := make([]uint64, len(parts))
	for index, part := range parts {
		if part == "" {
			return "", false, invalid
		}
		base := 10
		digits := part
		if len(part) >= 2 && (part[:2] == "0x" || part[:2] == "0X") {
			base, digits = 16, part[2:]
		} else if len(part) >= 2 && part[0] == '0' {
			base, digits = 8, part[1:]
		}
		if digits == "" {
			numbers[index] = 0
			continue
		}
		value, err := strconv.ParseUint(digits, base, 64)
		if err != nil {
			return "", false, invalid
		}
		numbers[index] = value
	}
	for index, value := range numbers[:len(numbers)-1] {
		_ = index
		if value > 255 {
			return "", false, invalid
		}
	}
	if numbers[len(numbers)-1] >= uint64(math.Pow(256, float64(5-len(numbers)))) {
		return "", false, invalid
	}
	ipv4 := numbers[len(numbers)-1]
	for index, value := range numbers[:len(numbers)-1] {
		ipv4 += value << (8 * (3 - index))
	}
	return strconv.FormatUint(ipv4>>24&255, 10) + "." + strconv.FormatUint(ipv4>>16&255, 10) + "." +
		strconv.FormatUint(ipv4>>8&255, 10) + "." + strconv.FormatUint(ipv4&255, 10), true, nil
}

// whatwgIPv6 serializes an IPv6 address as the URL standard does: lowercase hex groups, the first longest run of
// two or more zero groups compressed, and no dotted IPv4 tail.
func whatwgIPv6(ip net.IP) string {
	ip = ip.To16()
	groups := make([]uint16, 8)
	for index := range groups {
		groups[index] = uint16(ip[index*2])<<8 | uint16(ip[index*2+1])
	}
	bestStart, bestLength := -1, 1
	for index := 0; index < 8; {
		if groups[index] != 0 {
			index++
			continue
		}
		start := index
		for index < 8 && groups[index] == 0 {
			index++
		}
		if index-start > bestLength {
			bestStart, bestLength = start, index-start
		}
	}
	var out strings.Builder
	for index := 0; index < 8; index++ {
		if index == bestStart {
			if index == 0 {
				out.WriteString("::")
			} else {
				out.WriteString(":")
			}
			index += bestLength - 1
			continue
		}
		out.WriteString(strconv.FormatUint(uint64(groups[index]), 16))
		if index < 7 {
			out.WriteString(":")
		}
	}
	return out.String()
}

// ParseFetchURL is `new URL(value)` for absolute URLs; it fails for relative or malformed ones.
func ParseFetchURL(value string) (*FetchURL, error) {
	parsed, err := url.Parse(core.JSTrim(value))
	if err != nil || parsed.Scheme == "" || (parsed.Opaque != "" && specialPorts[strings.ToLower(parsed.Scheme)] != "") {
		return nil, errors.New("Invalid URL")
	}
	scheme := strings.ToLower(parsed.Scheme)
	parsed.Scheme = scheme
	result := &FetchURL{URL: parsed, Protocol: scheme + ":"}
	host := parsed.Hostname()
	if _, special := specialPorts[scheme]; special {
		if host == "" {
			return nil, errors.New("Invalid URL")
		}
		if unescaped, err := url.PathUnescape(host); err == nil {
			host = unescaped
		}
		host = strings.ToLower(host)
		if strings.Contains(parsed.Host, "[") {
			ip := net.ParseIP(host)
			if ip == nil || ip.To4() != nil && !strings.Contains(host, ":") {
				return nil, errors.New("Invalid URL")
			}
			result.Hostname = "[" + whatwgIPv6(ip) + "]"
		} else {
			ipv4, isIPv4, err := parseWHATWGIPv4(host)
			if err != nil {
				return nil, errors.New("Invalid URL")
			}
			if isIPv4 {
				host = ipv4
			}
			if strings.ContainsAny(host, " #%/:<>?@[\\]^|") {
				return nil, errors.New("Invalid URL")
			}
			result.Hostname = host
		}
		port := parsed.Port()
		if port != "" {
			number, err := strconv.ParseUint(port, 10, 32)
			if err != nil || number > 65535 {
				return nil, errors.New("Invalid URL")
			}
			port = strconv.FormatUint(number, 10)
			if port == specialPorts[scheme] {
				port = ""
			}
		}
		result.Port = port
		hostPort := result.Hostname
		if port != "" {
			hostPort += ":" + port
		}
		parsed.Host = hostPort
		if parsed.Path == "" {
			parsed.Path = "/"
		}
	} else {
		result.Hostname = strings.ToLower(host)
		result.Port = parsed.Port()
	}
	result.Href = parsed.String()
	return result, nil
}

func hostOf(u *FetchURL) string {
	if strings.HasPrefix(u.Hostname, "[") {
		return u.Hostname[1 : len(u.Hostname)-1]
	}
	return u.Hostname
}

// CheckFetchURL checks the URL rules: https on port 443 (any port with AnyPort) without credentials or a fragment
// (loopback hosts may use http and any port with AllowInsecureLocalhost), and, for an IP-literal host, a public
// address. It fails with a SafeFetchError (url or address) and returns the parsed URL.
func CheckFetchURL(value string, options SafeFetchAddressOptions) (*FetchURL, error) {
	u, err := ParseFetchURL(value)
	if err != nil {
		return nil, NewSafeFetchError("url", "Not an absolute URL")
	}
	if u.User != nil || u.Fragment != "" || strings.Contains(value, "#") {
		return nil, NewSafeFetchError("url", "Credentials and fragments are not allowed")
	}
	loopback := loopbackHosts[u.Hostname] && options.AllowInsecureLocalhost
	if !loopback && (u.Protocol != "https:" || (u.Port != "" && !options.AnyPort)) {
		if options.AnyPort {
			return nil, NewSafeFetchError("url", "Only https is allowed")
		}
		return nil, NewSafeFetchError("url", "Only https on port 443 is allowed")
	}
	if loopback && u.Protocol != "https:" && u.Protocol != "http:" {
		return nil, NewSafeFetchError("url", "Only http and https are allowed")
	}
	host := hostOf(u)
	if net.ParseIP(host) != nil && !loopback && !options.AllowPrivateNetworks && !IsPublicAddress(host) {
		return nil, NewSafeFetchError("address", "The address is not public")
	}
	return u, nil
}

// guardedDialer resolves a host and refuses it when any resolved address is not public (unless the options allow
// it), then connects to the first address that answers. IP-literal hosts are connected as they are: the URL rules
// already judged them (Node's http module skips the lookup for them too).
func guardedDialer(options SafeFetchAddressOptions, loopbackHost bool) func(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if net.ParseIP(host) != nil {
			return dialer.DialContext(ctx, network, address)
		}
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		allowed := func(entry net.IPAddr) bool {
			text := entry.IP.String()
			return options.AllowPrivateNetworks || IsPublicAddress(text) ||
				(loopbackHost && options.AllowInsecureLocalhost && isLoopbackAddress(text))
		}
		if len(addresses) == 0 {
			return nil, NewSafeFetchError("address", "The host resolves to a non-public address")
		}
		for _, entry := range addresses {
			if !allowed(entry) {
				return nil, NewSafeFetchError("address", "The host resolves to a non-public address")
			}
		}
		var last error
		for _, entry := range addresses {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(entry.IP.String(), port))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		return nil, last
	}
}

func guardedTransport(options SafeFetchAddressOptions, loopbackHost bool) *http.Transport {
	return &http.Transport{
		Proxy:             nil,
		DialContext:       guardedDialer(options, loopbackHost),
		DisableKeepAlives: true,
		ForceAttemptHTTP2: false,
	}
}

func noRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// safeFetchCause finds the SafeFetchError inside a transport error.
func safeFetchCause(err error) *SafeFetchError {
	var refused *SafeFetchError
	if errors.As(err, &refused) {
		return refused
	}
	return nil
}

// FetchJSONSafely GETs a JSON document under the SSRF rules. Any status other than 200 fails (redirect for 3xx,
// else status), as do a content type without "json", a body over MaxBytes, the deadline, and unparseable JSON.
// Every failure is a *SafeFetchError.
func FetchJSONSafely(ctx context.Context, value string, options SafeFetchOptions) (any, error) {
	address := SafeFetchAddressOptions{AllowPrivateNetworks: options.AllowPrivateNetworks, AllowInsecureLocalhost: options.AllowInsecureLocalhost}
	u, err := CheckFetchURL(value, address)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: guardedTransport(address, loopbackHosts[u.Hostname]), CheckRedirect: noRedirects}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(options.TimeoutMs)*time.Millisecond)
	defer cancel()
	fail := func(err error) (any, error) {
		if refused := safeFetchCause(err); refused != nil {
			return nil, refused
		}
		if ctx.Err() == context.DeadlineExceeded {
			return nil, NewSafeFetchError("timeout")
		}
		return nil, NewSafeFetchError("network")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.Href, nil)
	if err != nil {
		return fail(err)
	}
	request.Header.Set("accept", "application/json")
	request.Header.Set("user-agent", "better-iam")
	response, err := client.Do(request)
	if err != nil {
		return fail(err)
	}
	defer response.Body.Close()
	status := response.StatusCode
	if status >= 300 && status < 400 {
		return nil, NewSafeFetchError("redirect")
	}
	if status != 200 {
		return nil, NewSafeFetchError("status", "Unexpected status "+strconv.Itoa(status))
	}
	if !strings.Contains(strings.ToLower(response.Header.Get("content-type")), "json") {
		return nil, NewSafeFetchError("content-type")
	}
	if declared := response.Header.Get("content-length"); declared != "" {
		if size := jsNumber(declared); !math.IsNaN(size) && !math.IsInf(size, 0) && size > float64(options.MaxBytes) {
			return nil, NewSafeFetchError("size")
		}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, options.MaxBytes+1))
	if err != nil {
		return fail(err)
	}
	if int64(len(body)) > options.MaxBytes {
		return nil, NewSafeFetchError("size")
	}
	parsed, err := core.ParseJSON([]byte(decodeUTF8(body)))
	if err != nil {
		return nil, NewSafeFetchError("json")
	}
	return parsed, nil
}

// GuardedFetchOptions is what CreateGuardedFetch enforces besides the address rules.
type GuardedFetchOptions struct {
	SafeFetchAddressOptions
	// MaxBytes is the largest response body a caller may read; reading past it fails (nil: unlimited).
	MaxBytes *int64
}

// FetchFailedError is the TypeError('fetch failed') a guarded fetch rejects with; Cause is the SafeFetchError or
// network error.
type FetchFailedError struct{ Cause error }

func (e *FetchFailedError) Error() string { return "fetch failed" }
func (e *FetchFailedError) Unwrap() error { return e.Cause }

// Name is the JavaScript error name.
func (e *FetchFailedError) Name() string { return "TypeError" }

// GuardedFetch is a fetch under the SSRF rules (CreateGuardedFetch).
type GuardedFetch struct {
	options GuardedFetchOptions
}

// CreateGuardedFetch returns a fetch under the SSRF rules: the URL rules of CheckFetchURL, and a connect-time DNS
// check that refuses hosts resolving to non-public addresses. Redirects are never followed. Failures are a
// *FetchFailedError (or the context's error once ctx ends). The response body streams, bounded by MaxBytes when set.
func CreateGuardedFetch(options GuardedFetchOptions) *GuardedFetch {
	return &GuardedFetch{options: options}
}

// Do sends the request; a 3xx response is returned as it is (redirect: 'manual').
func (g *GuardedFetch) Do(request *http.Request) (*http.Response, error) {
	return g.do(request, false)
}

// DoRedirectError sends the request; a 3xx response fails with a redirect SafeFetchError (redirect: 'error').
func (g *GuardedFetch) DoRedirectError(request *http.Request) (*http.Response, error) {
	return g.do(request, true)
}

func (g *GuardedFetch) do(request *http.Request, redirectError bool) (*http.Response, error) {
	ctx := request.Context()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	u, err := CheckFetchURL(request.URL.String(), g.options.SafeFetchAddressOptions)
	if err != nil {
		return nil, &FetchFailedError{Cause: err}
	}
	outgoing := request.Clone(ctx)
	outgoing.URL = u.URL
	outgoing.Host = ""
	client := &http.Client{Transport: guardedTransport(g.options.SafeFetchAddressOptions, loopbackHosts[u.Hostname]), CheckRedirect: noRedirects}
	response, err := client.Do(outgoing)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var urlError *url.Error
		if errors.As(err, &urlError) {
			err = urlError.Err
		}
		return nil, &FetchFailedError{Cause: err}
	}
	status := response.StatusCode
	if status >= 300 && status < 400 && redirectError {
		response.Body.Close()
		return nil, &FetchFailedError{Cause: NewSafeFetchError("redirect")}
	}
	if g.options.MaxBytes != nil {
		if declared := response.Header.Get("content-length"); declared != "" {
			if size := jsNumber(declared); !math.IsNaN(size) && !math.IsInf(size, 0) && size > float64(*g.options.MaxBytes) {
				response.Body.Close()
				return nil, &FetchFailedError{Cause: NewSafeFetchError("size")}
			}
		}
		response.Body = &limitedBody{source: response.Body, remaining: *g.options.MaxBytes}
	}
	return response, nil
}

// limitedBody fails with a size SafeFetchError once more than the limit arrives.
type limitedBody struct {
	source    io.ReadCloser
	remaining int64
	failed    bool
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.failed {
		return 0, NewSafeFetchError("size")
	}
	n, err := b.source.Read(p)
	b.remaining -= int64(n)
	if b.remaining < 0 {
		b.failed = true
		b.source.Close()
		return 0, NewSafeFetchError("size")
	}
	return n, err
}

func (b *limitedBody) Close() error { return b.source.Close() }
