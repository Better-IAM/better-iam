package middleware

// The net/http integration: the Go counterpart of the Express and Fastify adapters (express.ts, fastify.ts), and the
// shared Integration the chi, gin and echo subpackages build on. Handler serves the IAM API (through the server's
// Node-style transport, so node protocol mounts such as the OAuth provider work) and gives every other request its
// helpers (FromRequest); RequireSession and Authorize are route guards; Wrap and HandleError answer IAM refusals
// returned by your handlers.

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

// maxBody is the largest request body the fallback path buffers for the IAM handler.
const maxBody = 2097152

// Options are the options every framework integration takes (IamExpressOptions, IamFastifyOptions, IamHonoOptions).
type Options struct {
	HelperOptions
	GuardOptions
	// Serve are the path prefixes the IAM server answers (default: its basePath). Add protocol mounts outside it,
	// e.g. "/oauth" or "/.well-known", so their requests reach the server's Node-style transport too.
	Serve []string
	// LoginPath is where page navigations (GET with Accept: text/html) go when signed out; ?next= carries the path.
	LoginPath string
	// StepUpPath is where page navigations go when the session must step up (?next=, ?reason=).
	StepUpPath string
}

// Integration is what every framework integration shares: the IAM source, the options, serving the IAM API, the
// per-request helpers, guards and refusal answers.
type Integration struct {
	resolve func(ctx context.Context) (IAM, error)
	options Options
}

// NewIntegration is an integration over one IAM instance.
func NewIntegration(source IAM, options Options) *Integration {
	return NewLazyIntegration(func(context.Context) (IAM, error) { return source, nil }, options)
}

// NewLazyIntegration is an integration over an IAM instance resolved on use (`() => T | Promise<T>`).
func NewLazyIntegration(resolve func(ctx context.Context) (IAM, error), options Options) *Integration {
	return &Integration{resolve: resolve, options: options}
}

// Resolve is the IAM instance.
func (i *Integration) Resolve(ctx context.Context) (IAM, error) { return i.resolve(ctx) }

// Options are the integration's options.
func (i *Integration) Options() Options { return i.options }

// RequestURL is the URL a request was sent to: its scheme (https when it arrived over TLS), Host and request target
// (the original one, before a router stripped a mount prefix).
func RequestURL(r *http.Request) (*url.URL, error) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if r.URL != nil && r.URL.IsAbs() && r.RequestURI == "" {
		return url.Parse(r.URL.String())
	}
	host := r.Host
	if host == "" && r.URL != nil {
		host = r.URL.Host
	}
	if host == "" {
		host = "localhost"
	}
	target := r.RequestURI
	if target == "" && r.URL != nil {
		target = r.URL.RequestURI()
	}
	if target == "" {
		target = "/"
	}
	if !strings.HasPrefix(target, "/") {
		parsed, err := url.Parse(target)
		if err != nil {
			return nil, err
		}
		target = parsed.RequestURI()
	}
	return url.Parse(scheme + "://" + host + target)
}

// prefixes are the paths the IAM server answers.
func (i *Integration) prefixes(iam IAM) []string {
	if len(i.options.Serve) > 0 {
		return i.options.Serve
	}
	if i.options.BasePath != "" {
		return []string{i.options.BasePath}
	}
	if provider, ok := iam.(EndpointProvider); ok && provider.IamEndpoint().BasePath != "" {
		return []string{provider.IamEndpoint().BasePath}
	}
	return []string{"/api/iam"}
}

// Serves is whether the IAM server answers the request (it is under one of the Serve prefixes).
func (i *Integration) Serves(iam IAM, r *http.Request) (bool, error) {
	target, err := RequestURL(r)
	if err != nil {
		return false, err
	}
	pathname := target.EscapedPath()
	if pathname == "" {
		pathname = "/"
	}
	for _, prefix := range i.prefixes(iam) {
		if UnderPath(pathname, prefix) {
			return true, nil
		}
	}
	return false, nil
}

// ServeIAM answers a request with the IAM server: through its Node-style transport when it has one, else through the
// fetch-style handler with the body buffered up to 2 MiB (413 beyond).
func (i *Integration) ServeIAM(w http.ResponseWriter, r *http.Request, iam IAM) {
	if node, ok := iam.(NodeHandler); ok {
		node.ServeHTTP(w, r)
		return
	}
	target, err := RequestURL(r)
	if err != nil {
		internalError(w)
		return
	}
	var body []byte
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Body != nil {
		// Bounded: an unauthenticated caller must not make the process buffer without limit.
		data, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil {
			internalError(w)
			return
		}
		if len(data) > maxBody {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_, _ = io.WriteString(w, "Request too large")
			return
		}
		body = data
	}
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), reader)
	if err != nil {
		internalError(w)
		return
	}
	request.Header = r.Header.Clone()
	request.RemoteAddr = r.RemoteAddr
	request.TLS = r.TLS
	WriteResponse(w, iam.Handle(request))
}

// WriteResponse writes an IAM handler answer to a ResponseWriter.
func WriteResponse(w http.ResponseWriter, response *server.Response) {
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

func internalError(w http.ResponseWriter) {
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}

type helpersKey struct{}

// WithHelpers is ctx carrying the request helpers.
func WithHelpers(ctx context.Context, helpers *Helpers) context.Context {
	return context.WithValue(ctx, helpersKey{}, helpers)
}

// FromContext is the request helpers ctx carries (nil when none).
func FromContext(ctx context.Context) *Helpers {
	helpers, _ := ctx.Value(helpersKey{}).(*Helpers)
	return helpers
}

// FromRequest is the request helpers the integration attached to a request (nil when none).
func FromRequest(r *http.Request) *Helpers { return FromContext(r.Context()) }

// NewHelpers builds the helpers of a request whose Set-Cookie headers go on header (the response's).
func (i *Integration) NewHelpers(header http.Header, r *http.Request) (*Helpers, error) {
	target, err := RequestURL(r)
	if err != nil {
		return nil, err
	}
	return NewHelpers(i.resolve, RequestBinding{
		URL:       target,
		Header:    r.Header,
		SetCookie: func(cookie string) { header.Add("Set-Cookie", cookie) },
	}, i.options.HelperOptions), nil
}

// HelpersFor is the request's helpers, created on first use, and the request carrying them.
func (i *Integration) HelpersFor(w http.ResponseWriter, r *http.Request) (*Helpers, *http.Request, error) {
	if existing := FromRequest(r); existing != nil {
		return existing, r, nil
	}
	created, err := i.NewHelpers(w.Header(), r)
	if err != nil {
		return nil, r, err
	}
	return created, r.WithContext(WithHelpers(r.Context(), created)), nil
}

// OriginCheck is the Origin check of a guard (nil when CSRF is off): the request and the trusted origins (the IAM
// origin and TrustedOrigins).
func (i *Integration) OriginCheck(iam IAM, r *http.Request) (*OriginCheck, error) {
	if i.options.CSRF != nil && !*i.options.CSRF {
		return nil, nil
	}
	target, err := RequestURL(r)
	if err != nil {
		return nil, err
	}
	trusted := []string{""}
	if provider, ok := iam.(EndpointProvider); ok {
		trusted[0] = provider.IamEndpoint().Origin
	}
	trusted = append(trusted, i.options.TrustedOrigins...)
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	return &OriginCheck{Method: method, URL: target, Header: r.Header, TrustedOrigins: trusted}, nil
}

// Guard runs a guard for a framework request: the Origin check (unless CSRF is off), the session, step-up and the
// authorization. It answers the session or the refusal.
func Guard[Req any](ctx context.Context, i *Integration, helpers *Helpers, request Req, r *http.Request, spec GuardSpec[Req]) (*core.Object, error) {
	iam, err := i.resolve(ctx)
	if err != nil {
		return nil, err
	}
	origin, err := i.OriginCheck(iam, r)
	if err != nil {
		return nil, err
	}
	return EnforceGuard(ctx, helpers, request, spec, origin)
}

// Answer answers an IAM refusal: a 303 redirect to the login / step-up page for page navigations, else the JSON error
// envelope (no-store). It is false, writing nothing, when err is not a refusal.
func (i *Integration) Answer(w http.ResponseWriter, r *http.Request, err error) bool {
	refusal, ok := RefusalOf(err)
	if !ok {
		return false
	}
	target, parseErr := RequestURL(r)
	if parseErr != nil {
		target = &url.URL{Path: "/"}
	}
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	answer := RefusalResponse(refusal, RefusalRequest{URL: target, Header: r.Header, Method: method}, Pages{LoginPath: i.options.LoginPath, StepUpPath: i.options.StepUpPath})
	if answer.Redirect != "" {
		w.Header().Set("Location", answer.Redirect)
		w.WriteHeader(http.StatusSeeOther)
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(answer.Status)
	_, _ = io.WriteString(w, answer.Body)
	return true
}

// Middleware is the net/http integration (createIamExpress / createIamFastify).
//
//	iamHTTP := middleware.New(iam, middleware.Options{LoginPath: "/login"})
//	mux.Handle("GET /projects/{id}", iamHTTP.Authorize("projects:read", middleware.AuthorizeSpec[*http.Request]{
//		Resource: func(r *http.Request, _ *core.Object) (middleware.ResourceRef, error) {
//			return middleware.ResourceRef{Type: "project", ID: r.PathValue("id")}, nil
//		},
//	})(handler))
//	http.ListenAndServe(":3000", iamHTTP.Handler(mux))
type Middleware struct {
	*Integration
}

// New is the net/http integration over a composed server.
func New(iam *server.BetterIam, options Options) *Middleware { return NewWith(Server(iam), options) }

// NewWith is the net/http integration over any IAM implementation.
func NewWith(source IAM, options Options) *Middleware {
	return &Middleware{Integration: NewIntegration(source, options)}
}

// NewLazy is the net/http integration over an IAM instance resolved on use.
func NewLazy(resolve func(ctx context.Context) (IAM, error), options Options) *Middleware {
	return &Middleware{Integration: NewLazyIntegration(resolve, options)}
}

// Helpers is the request's helpers, created on first use, and the request carrying them.
func (m *Middleware) Helpers(w http.ResponseWriter, r *http.Request) (*Helpers, *http.Request, error) {
	return m.HelpersFor(w, r)
}

// Handler serves the IAM API under the Serve prefixes and gives every other request its helpers (FromRequest) before
// next (404 when next is nil).
func (m *Middleware) Handler(next http.Handler) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		iam, err := m.resolve(r.Context())
		if err != nil {
			internalError(w)
			return
		}
		serves, err := m.Serves(iam, r)
		if err != nil {
			internalError(w)
			return
		}
		if serves {
			m.ServeIAM(w, r, iam)
			return
		}
		_, r, err = m.HelpersFor(w, r)
		if err != nil {
			internalError(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) guard(spec GuardSpec[*http.Request]) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			helpers, r, err := m.HelpersFor(w, r)
			if err == nil {
				_, err = Guard(r.Context(), m.Integration, helpers, r, r, spec)
			}
			if err != nil {
				if !m.Answer(w, r, err) {
					internalError(w)
				}
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireSession is a guard requiring a session (and stepUp, when given).
func (m *Middleware) RequireSession(stepUp *StepUpRequirement) func(http.Handler) http.Handler {
	return m.guard(GuardSpec[*http.Request]{StepUp: stepUp})
}

// Authorize is a guard requiring a session allowed to perform action (default resource: the tenant). Resource and
// TenantID receive the request (read path values with r.PathValue).
func (m *Middleware) Authorize(action string, spec AuthorizeSpec[*http.Request]) func(http.Handler) http.Handler {
	return m.guard(spec.Guard(action))
}

// HandleError answers an IAM refusal (the JSON error envelope, or a login / step-up redirect for pages); false when
// err is not one.
func (m *Middleware) HandleError(w http.ResponseWriter, r *http.Request, err error) bool {
	return m.Answer(w, r, err)
}

// Wrap adapts a handler that returns an error (the errorHandler): IAM refusals become the JSON error envelope (or a
// login / step-up redirect for pages), other errors a 500. An error after the response started aborts it.
func (m *Middleware) Wrap(handler func(w http.ResponseWriter, r *http.Request) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tracked := &trackingWriter{ResponseWriter: w}
		err := handler(tracked, r)
		if err == nil {
			return
		}
		if tracked.wrote {
			panic(http.ErrAbortHandler)
		}
		if !m.Answer(w, r, err) {
			internalError(w)
		}
	})
}

// trackingWriter records whether the response started (res.headersSent).
type trackingWriter struct {
	http.ResponseWriter
	wrote bool
}

func (t *trackingWriter) WriteHeader(status int) {
	t.wrote = true
	t.ResponseWriter.WriteHeader(status)
}

func (t *trackingWriter) Write(data []byte) (int, error) {
	t.wrote = true
	return t.ResponseWriter.Write(data)
}

func (t *trackingWriter) Flush() {
	t.wrote = true
	if flusher, ok := t.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (t *trackingWriter) Unwrap() http.ResponseWriter { return t.ResponseWriter }
