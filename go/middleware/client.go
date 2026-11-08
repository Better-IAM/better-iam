package middleware

// The in-process client of the request helpers (index.ts inProcessClient): calls go to the IAM handler in this
// process with the request's credential, and the cookies it answers with are set on this response and count for the
// rest of the request.

import (
	"bytes"
	"context"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

// internalBaseURL is the client's base URL; its path under /api/iam is moved onto the IAM mount.
const internalBaseURL = "http://better-iam.internal"

// ClientError is a refusal the in-process client answers (IamClientError): the IAM code, message and HTTP status.
type ClientError struct {
	Code    string
	Message string
	// Status is the HTTP status (0 for errors raised before the request).
	Status int
	// RetryAfterMs is how long a rate-limited caller should wait, when the server said.
	RetryAfterMs *float64
	// Region and Location are set for WRONG_REGION refusals.
	Region   string
	Location string
}

func (e *ClientError) Error() string { return e.Message }

// Name is the JavaScript error name ("IamClientError").
func (e *ClientError) Name() string { return "IamClientError" }

// Client is the in-process client of one request (helpers.client). Call is the typed client's transport; RoundTrip
// makes it an http.RoundTripper, so any HTTP client of the IAM API (base URL http://better-iam.internal/api/iam) can
// use it.
type Client struct {
	helpers *Helpers
}

var (
	routeSegmentPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)
	reservedSegments    = map[string]bool{
		"then": true, "catch": true, "finally": true, "toJSON": true, "constructor": true, "prototype": true,
		"__proto__": true,
	}
	locationPattern = regexp.MustCompile(`^https?://`)
)

func routeSegment(value string) bool {
	return routeSegmentPattern.MatchString(value) && !reservedSegments[value]
}

// Call is POST /api/iam/{path} with input as the JSON body (`{}` when nil); it answers the envelope's `data`, or the
// refusal as a *ClientError.
func (c *Client) Call(ctx context.Context, path string, input any) (any, error) {
	valid := path != ""
	for _, segment := range strings.Split(path, "/") {
		valid = valid && routeSegment(segment)
	}
	if !valid {
		return nil, &ClientError{Code: "INVALID_PATH", Message: "IAM routes must use plain relative path segments"}
	}
	header := http.Header{}
	// These headers are invariant: the server's CSRF boundary requires both.
	header.Set("Content-Type", "application/json")
	header.Set("X-Better-Iam", "1")
	if input == nil {
		input = core.NewObject()
	}
	body, ok, err := core.Stringify(core.Normalize(input))
	if err != nil {
		return nil, &ClientError{Code: "INVALID_INPUT", Message: "Request input must be serializable JSON"}
	}
	if !ok {
		body = "{}"
	}
	target, err := url.Parse(internalBaseURL + "/api/iam/" + path)
	if err != nil {
		return nil, &ClientError{Code: "INVALID_PATH", Message: "IAM routes must use plain relative path segments"}
	}
	response, err := c.helpers.fetch(ctx, http.MethodPost, target, header, []byte(body), true)
	if err != nil {
		return nil, err
	}
	fail := func(code, message string, retryAfterMs *float64) *ClientError {
		return &ClientError{Code: code, Message: message, Status: response.Status, RetryAfterMs: retryAfterMs}
	}
	parsed, err := core.ParseJSON(response.Body)
	envelope, isObject := parsed.(*core.Object)
	if err != nil || !isObject {
		return nil, fail("INVALID_RESPONSE", "The IAM server returned an invalid response", nil)
	}
	if failure, present := envelope.Lookup("error"); present {
		known, _ := failure.(*core.Object)
		code, codeOK := stringMember(known, "code")
		message, messageOK := stringMember(known, "message")
		if !codeOK || !messageOK {
			return nil, fail("INVALID_RESPONSE", "The IAM server returned an invalid error response", nil)
		}
		var retryAfterMs *float64
		if fromBody, ok := known.Get("retryAfterMs").(float64); ok {
			retryAfterMs = &fromBody
		} else if header := jsNumber(response.Header.Get("Retry-After")); !math.IsNaN(header) && !math.IsInf(header, 0) && header > 0 {
			wait := header * 1000
			retryAfterMs = &wait
		}
		refusal := fail(code, message, retryAfterMs)
		if region, ok := known.Get("region").(string); ok {
			refusal.Region = region
		}
		if location, ok := known.Get("location").(string); ok && locationPattern.MatchString(location) {
			refusal.Location = location
		}
		return nil, refusal
	}
	if response.Status < 200 || response.Status > 299 {
		return nil, fail("HTTP_ERROR", "The IAM server rejected the request", nil)
	}
	data, present := envelope.Lookup("data")
	if !present {
		return nil, fail("INVALID_RESPONSE", "The IAM server returned an invalid response", nil)
	}
	return data, nil
}

func stringMember(object *core.Object, name string) (string, bool) {
	if object == nil {
		return "", false
	}
	value, ok := object.Get(name).(string)
	return value, ok
}

// jsNumber is Number(string): "" is 0, anything else not numeric is NaN.
func jsNumber(value string) float64 {
	trimmed := core.JSTrim(value)
	if trimmed == "" {
		return 0
	}
	number, err := strconv.ParseFloat(trimmed, 64)
	if err != nil {
		if strings.HasPrefix(trimmed, "0x") || strings.HasPrefix(trimmed, "0X") {
			if hex, err := strconv.ParseUint(trimmed[2:], 16, 64); err == nil {
				return float64(hex)
			}
		}
		return math.NaN()
	}
	return number
}

// RoundTrip sends an HTTP request to the IAM handler in this process (the client's fetch).
func (c *Client) RoundTrip(request *http.Request) (*http.Response, error) {
	var body []byte
	hasBody := false
	if request.Body != nil && request.Body != http.NoBody {
		data, err := io.ReadAll(request.Body)
		_ = request.Body.Close()
		if err != nil {
			return nil, err
		}
		body, hasBody = data, true
	}
	method := request.Method
	if method == "" {
		method = http.MethodPost
	}
	response, err := c.helpers.fetch(request.Context(), method, request.URL, request.Header, body, hasBody)
	if err != nil {
		return nil, err
	}
	header := response.Header.Clone()
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{
		Status:     strconv.Itoa(response.Status) + " " + http.StatusText(response.Status),
		StatusCode: response.Status, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: header, Body: io.NopCloser(bytes.NewReader(response.Body)), ContentLength: int64(len(response.Body)),
		Request: request,
	}, nil
}

// fetch is the in-process transport: it moves the client's /api/iam path onto the IAM mount, forwards the request's
// credential headers and cookies, sends the IAM origin, and applies the cookies the answer sets to this request.
func (h *Helpers) fetch(ctx context.Context, method string, target *url.URL, header http.Header, body []byte, hasBody bool) (*server.Response, error) {
	iam, err := h.resolve(ctx)
	if err != nil {
		return nil, err
	}
	origin := ""
	if h.binding.URL != nil {
		origin = URLOrigin(h.binding.URL.Scheme + "://" + h.binding.URL.Host + "/")
	}
	mount := h.options.BasePath
	if provider, ok := iam.(EndpointProvider); ok {
		endpoint := provider.IamEndpoint()
		if endpoint.Origin != "" {
			origin = endpoint.Origin
		}
		if mount == "" {
			mount = endpoint.BasePath
		}
	}
	if mount == "" {
		mount = "/api/iam"
	}
	outgoing := header.Clone()
	if outgoing == nil {
		outgoing = http.Header{}
	}
	incoming := h.Header()
	for _, name := range append(append([]string{}, forwardedHeaders...), "cookie") {
		value, present := headerGet(incoming, name)
		if _, exists := headerGet(outgoing, name); present && !exists {
			outgoing.Set(name, value)
		}
	}
	outgoing.Set("Origin", origin)
	// With organization addresses (`hosts`), the call keeps the host the visitor is on, so the server pins it to that
	// organization (and fills in its tenant ID) exactly as it would a browser call from the page.
	address := origin
	if _, ok := iam.(HostResolver); ok && h.binding.URL != nil {
		scheme := "http"
		if parsed, err := url.Parse(origin); err == nil && parsed.Scheme != "" {
			scheme = parsed.Scheme
		}
		address = scheme + "://" + h.binding.URL.Host
	}
	pathname := target.EscapedPath()
	rest := ""
	if len(pathname) > len("/api/iam") {
		rest = pathname[len("/api/iam"):]
	}
	search := ""
	if target.RawQuery != "" {
		search = "?" + target.RawQuery
	}
	var reader io.Reader
	if hasBody {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, address+mount+rest+search, reader)
	if err != nil {
		return nil, err
	}
	request.Header = outgoing
	response := iam.Handle(request)
	issued := response.Header.Values("Set-Cookie")
	for _, cookie := range issued {
		h.setCookie(cookie)
	}
	if len(issued) > 0 {
		h.forget()
	}
	return response, nil
}
