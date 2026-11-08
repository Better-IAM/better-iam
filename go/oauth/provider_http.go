package oauth

// The provider's HTTP layer: the request context (oidc-provider's OIDCContext on Koa), signed cookies (cookies +
// keygrip), parameter assembly, the router (case-insensitive, trailing slash tolerant), CORS, error rendering and
// the mount (nodeHandler).

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"html"
	"io"
	"mime"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Better-IAM/better-iam/go/core"
)

// oidcCtx is one request through the provider.
type oidcCtx struct {
	p      *Provider
	ctx    context.Context
	r      *http.Request
	method string
	// path is the provider-relative path the router matched; originalURL is the request target as received.
	path        string
	originalURL string
	route       string
	routeParams map[string]string
	query       *core.Object
	body        *core.Object
	bodyParsed  bool
	params      *core.Object
	allowList   []string

	status      int
	statusSet   bool
	header      http.Header
	setCookies  []string
	respBody    any
	contentType string
	location    string

	client             *oidcClient
	session            *model
	grant              *model
	account            *account
	interaction        *model
	par                *model
	deviceCode         *model
	accessToken        *model
	refreshToken       *model
	rotatedRefresh     *model
	authorizationCode  *model
	resourceServers    []*resourceServerInfo
	trusted            []string
	result             *core.Object
	claims             *core.Object
	redirectURIChecked bool
	noClient           bool
	dpop               *dpopProof
	dpopValidated      bool
	accessTokenValue   string
	exchange           *exchangeState
	corsClientBased    bool
	idTokenHint        *core.Object
	registration       *registrationContext
	bodyNotObject      bool
}

type exchangeState struct {
	act       *core.Object
	remaining int64
}

func (oc *oidcCtx) secure() bool {
	if oc.r.TLS != nil {
		return true
	}
	if oc.p.config.TrustProxy {
		proto := strings.TrimSpace(strings.Split(oc.r.Header.Get("x-forwarded-proto"), ",")[0])
		return proto == "https"
	}
	return false
}

func (oc *oidcCtx) protocol() string {
	if oc.secure() {
		return "https"
	}
	return "http"
}

func (oc *oidcCtx) host() string {
	if oc.p.config.TrustProxy {
		if forwarded := oc.r.Header.Get("x-forwarded-host"); forwarded != "" {
			return strings.TrimSpace(strings.Split(forwarded, ",")[0])
		}
	}
	return oc.r.Host
}

func (oc *oidcCtx) ip() string {
	if oc.p.config.TrustProxy {
		if forwarded := oc.r.Header.Get("x-forwarded-for"); forwarded != "" {
			return strings.TrimSpace(strings.Split(forwarded, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(oc.r.RemoteAddr)
	if err != nil {
		return oc.r.RemoteAddr
	}
	return host
}

// href is Koa's ctx.href: origin plus the original request target.
func (oc *oidcCtx) href() string { return oc.protocol() + "://" + oc.host() + oc.originalURL }

// mountPath is where the provider is mounted for this request (urlFor's derivation from originalUrl).
func (oc *oidcCtx) mountPath() string {
	current := oc.path
	if raw := oc.r.URL.RawQuery; raw != "" {
		current += "?" + raw
	}
	index := strings.Index(oc.originalURL, current)
	if index <= 0 {
		return ""
	}
	return oc.originalURL[:index]
}

var routePaths = map[string]string{
	"authorization": "/auth", "resume": "/auth/:uid", "userinfo": "/me", "token": "/token", "jwks": "/jwks",
	"discovery": "/.well-known/openid-configuration", "registration": "/reg", "client": "/reg/:clientId",
	"revocation": "/token/revocation", "introspection": "/token/introspection", "end_session": "/session/end",
	"end_session_confirm": "/session/end/confirm", "end_session_success": "/session/end/success",
	"device_authorization": "/device/auth", "code_verification": "/device", "device_resume": "/device/:uid",
	"pushed_authorization_request": "/request",
}

// pathFor is provider.pathFor without the mount path.
func pathFor(name string, params map[string]string) string {
	path := routePaths[name]
	for key, value := range params {
		path = strings.Replace(path, ":"+key, encodeURIComponent(value), 1)
	}
	return path
}

// urlFor is OIDCContext#urlFor.
func (oc *oidcCtx) urlFor(name string, params map[string]string, query [][2]string) string {
	path := oc.mountPath() + pathFor(name, params)
	if len(query) > 0 {
		parts := make([]string, len(query))
		for index, pair := range query {
			parts[index] = queryEscape(pair[0]) + "=" + queryEscape(pair[1])
		}
		path += "?" + strings.Join(parts, "&")
	}
	base, err := parseURL(oc.href())
	if err != nil {
		return path
	}
	target, err := base.URL.Parse(path)
	if err != nil {
		return path
	}
	parsed, err := parseURL(target.String())
	if err != nil {
		return target.String()
	}
	return parsed.Href
}

// queryEscape is Node's querystring.escape.
func queryEscape(s string) string {
	const safe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()"
	var b strings.Builder
	for _, c := range utf8Bytes(s) {
		if strings.IndexByte(safe, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteString("%" + strings.ToUpper(strconv.FormatInt(int64(c)>>4, 16)) + strings.ToUpper(strconv.FormatInt(int64(c)&15, 16)))
	}
	return b.String()
}

// --- cookies (cookies + keygrip) -------------------------------------------------------------------------------------

func (p *Provider) keygripSign(data string) string {
	mac := hmac.New(sha1.New, []byte(p.cookieKeys[0]))
	mac.Write([]byte(data))
	return strings.NewReplacer("/", "_", "+", "-", "=", "").Replace(base64.StdEncoding.EncodeToString(mac.Sum(nil)))
}

func (p *Provider) keygripIndex(data, digest string) int {
	for index, key := range p.cookieKeys {
		mac := hmac.New(sha1.New, []byte(key))
		mac.Write([]byte(data))
		expected := strings.NewReplacer("/", "_", "+", "-", "=", "").Replace(base64.StdEncoding.EncodeToString(mac.Sum(nil)))
		if constantEquals(expected, digest) {
			return index
		}
	}
	return -1
}

func rawCookie(r *http.Request, name string) (string, bool) {
	header := r.Header.Get("cookie")
	if header == "" {
		return "", false
	}
	pattern := regexp.MustCompile(`(?:^|;) *` + regexp.QuoteMeta(name) + `=([^;]*)`)
	match := pattern.FindStringSubmatch(header)
	if match == nil {
		return "", false
	}
	value := match[1]
	if strings.HasPrefix(value, `"`) && len(value) >= 2 {
		value = value[1 : len(value)-1]
	}
	return value, true
}

// getCookie is cookies.get(name, { signed: true }).
func (oc *oidcCtx) getCookie(name string) string {
	value, ok := rawCookie(oc.r, name)
	if !ok {
		return ""
	}
	remote, ok := rawCookie(oc.r, name+".sig")
	if !ok || remote == "" {
		return ""
	}
	index := oc.p.keygripIndex(name+"="+value, remote)
	if index < 0 {
		oc.addCookie(name+".sig", "", cookieOptions{path: "/", httpOnly: true, unsigned: true})
		return ""
	}
	if index > 0 {
		oc.addCookie(name+".sig", oc.p.keygripSign(name+"="+value), cookieOptions{path: "/", httpOnly: true, unsigned: true})
	}
	return value
}

type cookieOptions struct {
	path     string
	maxAge   int64
	httpOnly bool
	sameSite string
	secure   *bool
	unsigned bool
}

func (p *Provider) longCookie() cookieOptions {
	secure := p.secure
	return cookieOptions{path: "/", httpOnly: true, sameSite: "lax", secure: &secure}
}

func (p *Provider) shortCookie(path string, maxAge int64) cookieOptions {
	secure := p.secure
	return cookieOptions{path: path, maxAge: maxAge, httpOnly: true, sameSite: "lax", secure: &secure}
}

var errInsecureCookie = errors.New("Cannot send secure cookie over unencrypted connection")

// setCookie is cookies.set(name, value, opts): a signed cookie and its `.sig` companion.
func (oc *oidcCtx) setCookie(name, value string, options cookieOptions) error {
	if options.secure != nil && *options.secure && !oc.secure() {
		return errInsecureCookie
	}
	oc.addCookie(name, value, options)
	if !options.unsigned {
		signature := oc.p.keygripSign(name + "=" + value)
		oc.addCookie(name+".sig", signature, options)
	}
	return nil
}

func (oc *oidcCtx) addCookie(name, value string, options cookieOptions) {
	header := name + "=" + value
	if options.path == "" {
		options.path = "/"
	}
	header += "; path=" + options.path
	if value == "" {
		header += "; expires=" + time.Unix(0, 0).UTC().Format(http.TimeFormat)
	} else if options.maxAge > 0 {
		header += "; expires=" + time.UnixMilli(oc.p.now()+options.maxAge).UTC().Format(http.TimeFormat)
	}
	if options.sameSite != "" {
		header += "; samesite=" + options.sameSite
	}
	secure := oc.secure()
	if options.secure != nil {
		secure = *options.secure
	}
	if secure {
		header += "; secure"
	}
	if options.httpOnly {
		header += "; httponly"
	}
	oc.setCookies = append(oc.setCookies, header)
}

// --- parameters -------------------------------------------------------------------------------------------------------

var errBodyTooLarge = errors.New("request entity too large")

// parseBody is shared/selective_body.js for application/x-www-form-urlencoded (or JSON for registration).
func (oc *oidcCtx) parseBody(contentType string) error {
	if oc.bodyParsed {
		return nil
	}
	oc.bodyParsed = true
	declared := oc.r.Header.Get("content-type")
	mediaType, _, _ := mime.ParseMediaType(declared)
	if declared != "" && strings.EqualFold(mediaType, contentType) {
		raw, err := io.ReadAll(io.LimitReader(oc.r.Body, 56*1024+1))
		if err != nil || len(raw) > 56*1024 {
			return errInvalidRequest("failed to parse the request body")
		}
		if contentType == "application/json" {
			parsed, err := core.ParseJSON(raw)
			if err != nil {
				return errInvalidRequest("failed to parse the request body")
			}
			if body, ok := parsed.(*core.Object); ok {
				oc.body = body
			} else {
				oc.body = nil
				oc.bodyNotObject = true
			}
			return nil
		}
		oc.body = queryParse(decodeUTF8(raw))
		return nil
	}
	if declared != "" {
		return errInvalidRequest("only " + contentType + " content-type bodies are supported on " + oc.method + " " + oc.path)
	}
	oc.body = core.NewObject()
	return nil
}

// assembleParams is shared/assemble_params.js: each allowed parameter, ” becoming undefined.
func (oc *oidcCtx) assembleParams(allowList []string) {
	source := oc.query
	if oc.method == http.MethodPost {
		source = oc.body
		if source == nil {
			source = core.NewObject()
		}
	}
	oc.allowList = allowList
	params := core.NewObject()
	for _, name := range allowList {
		value := source.Get(name)
		if !truthy(value) {
			value = core.Undefined
		}
		params.Set(name, value)
	}
	oc.params = params
}

// param is a string parameter ("" when absent or not a string).
func (oc *oidcCtx) param(name string) string {
	value, _ := oc.params.Get(name).(string)
	return value
}

func (oc *oidcCtx) hasParam(name string) bool { return !isUndefined(oc.params.Get(name)) }

// rejectDupes is shared/reject_dupes.js.
func (oc *oidcCtx) rejectDupes(except, only []string) error {
	var names []string
	for _, key := range oc.params.Keys() {
		if _, isArray := oc.params.Get(key).([]any); !isArray {
			continue
		}
		if except != nil && contains(except, key) {
			continue
		}
		if except == nil && only != nil && !contains(only, key) {
			continue
		}
		names = append(names, key)
		oc.params.Set(key, core.Undefined)
	}
	if len(names) > 0 {
		return errInvalidRequest(formatList(names, false) + " " + pluralize("parameter", len(names)) + " must not be provided twice")
	}
	return nil
}

// presence is helpers/validate_presence.js.
func (oc *oidcCtx) presence(required ...string) error {
	var missing []string
	for _, name := range required {
		if isUndefined(oc.params.Get(name)) {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return errInvalidRequest("missing required " + pluralize("parameter", len(missing)) + " " + formatList(missing, false))
	}
	return nil
}

func (oc *oidcCtx) plainParams() *core.Object {
	out := core.NewObject()
	oc.params.Entries(func(key string, value any) bool {
		if !isUndefined(value) {
			out.SetRaw(key, value)
		}
		return true
	})
	return out
}

// --- responses --------------------------------------------------------------------------------------------------------

func (oc *oidcCtx) setStatus(status int) { oc.status, oc.statusSet = status, true }

func (oc *oidcCtx) setJSON(value any) {
	oc.respBody = value
	oc.contentType = "application/json; charset=utf-8"
	if !oc.statusSet {
		oc.setStatus(200)
	}
}

func (oc *oidcCtx) setHTML(text string) {
	oc.respBody = text
	oc.contentType = "text/html; charset=utf-8"
	if !oc.statusSet {
		oc.setStatus(200)
	}
}

// setText is Koa's string body: HTML when it starts with '<', plain text otherwise.
func (oc *oidcCtx) setText(text string) {
	if strings.HasPrefix(core.JSTrim(text), "<") {
		oc.setHTML(text)
		return
	}
	oc.respBody = text
	oc.contentType = "text/plain; charset=utf-8"
	if !oc.statusSet {
		oc.setStatus(200)
	}
}

// redirect is Koa's ctx.redirect after ctx.status = 303.
func (oc *oidcCtx) redirect(target string) {
	oc.setStatus(303)
	oc.location = target
	if oc.accepts("html") {
		oc.respBody = "Redirecting to " + html.EscapeString(target) + "."
		oc.contentType = "text/html; charset=utf-8"
	} else {
		oc.respBody = "Redirecting to " + target + "."
		oc.contentType = "text/plain; charset=utf-8"
	}
}

// accepts is a small negotiator: true when the Accept header admits the type (html or json).
func (oc *oidcCtx) accepts(kind string) bool {
	return acceptQuality(oc.r.Header.Get("accept"), mimeOf(kind)) > 0
}

func mimeOf(kind string) string {
	if kind == "html" {
		return "text/html"
	}
	return "application/json"
}

// acceptQuality is the q of the most specific Accept entry matching a media type (1 without an Accept header).
func acceptQuality(header, mediaType string) float64 {
	if strings.TrimSpace(header) == "" {
		return 1
	}
	best, bestSpecificity := 0.0, -1
	major := strings.SplitN(mediaType, "/", 2)[0]
	for _, part := range strings.Split(header, ",") {
		fields := strings.Split(strings.TrimSpace(part), ";")
		value := strings.ToLower(strings.TrimSpace(fields[0]))
		q := 1.0
		for _, field := range fields[1:] {
			field = strings.TrimSpace(field)
			if strings.HasPrefix(field, "q=") {
				if parsed, err := strconv.ParseFloat(field[2:], 64); err == nil {
					q = parsed
				}
			}
		}
		specificity := -1
		switch {
		case value == mediaType:
			specificity = 2
		case value == major+"/*":
			specificity = 1
		case value == "*/*":
			specificity = 0
		}
		if specificity > bestSpecificity {
			best, bestSpecificity = q, specificity
		}
	}
	return best
}

// preferred is ctx.accepts('json', 'html'): the better of the two, json on ties.
func (oc *oidcCtx) preferred() string {
	header := oc.r.Header.Get("accept")
	json, htmlQ := acceptQuality(header, "application/json"), acceptQuality(header, "text/html")
	if json <= 0 && htmlQ <= 0 {
		return ""
	}
	if htmlQ > json {
		return "html"
	}
	return "json"
}

func (oc *oidcCtx) write(w http.ResponseWriter) {
	for key, values := range oc.header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	for _, cookie := range oc.setCookies {
		w.Header().Add("Set-Cookie", cookie)
	}
	if oc.location != "" {
		w.Header().Set("Location", oc.location)
	}
	status := oc.status
	if !oc.statusSet {
		status = 404
		if oc.respBody == nil {
			oc.respBody = "Not Found"
			oc.contentType = "text/plain; charset=utf-8"
		}
	}
	var body []byte
	switch value := oc.respBody.(type) {
	case nil:
	case string:
		body = []byte(value)
	case []byte:
		body = value
	default:
		body = []byte(stringify(value))
	}
	if oc.contentType != "" && body != nil {
		w.Header().Set("Content-Type", oc.contentType)
	}
	if status == 204 || status == 304 {
		body = nil
	}
	if body != nil {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	}
	w.WriteHeader(status)
	if oc.method != http.MethodHead && body != nil {
		_, _ = w.Write(body)
	}
}

// --- error rendering ------------------------------------------------------------------------------------------------

// renderError is the configured renderError: a JSON body with a generic description.
func (oc *oidcCtx) renderError(out *outBody) {
	oc.setJSON(core.NewObject("error", out.Error, "error_description", "The identity request could not be completed."))
}

func statusOf(err error) int {
	if e, ok := asOIDC(err); ok {
		return e.Status
	}
	return 500
}

func outObject(out *outBody) *core.Object {
	o := core.NewObject()
	for _, pair := range out.object().items {
		o.Set(pair[0], pair[1])
	}
	return o
}

// handleError is shared/error_handler.js.
func (oc *oidcCtx) handleError(err error) {
	out := errOut(err, "", false)
	oc.setStatus(statusOf(err))
	if oc.session != nil && (oc.route == "code_verification" || oc.route == "device_resume") {
		oc.generateXsrf()
		secret := str(obj(oc.session.data, "state"), "secret")
		form := userCodeInputForm(oc.urlFor("code_verification", nil, nil), secret, rerenderCode(err))
		if e, ok := asOIDC(err); ok && e.rerender {
			oc.setStatus(200)
		}
		page, renderErr := oc.p.config.RenderDevicePage(oc.ctx, DevicePageInput{Kind: "input", Form: form})
		if renderErr != nil {
			oc.setStatus(500)
			oc.setJSON(outObject(errOut(renderErr, "", false)))
			return
		}
		oc.setText(page)
		return
	}
	if oc.preferred() == "html" {
		oc.renderError(out)
		return
	}
	oc.setJSON(outObject(out))
}

func rerenderCode(err error) string {
	if e, ok := asOIDC(err); ok {
		return e.userCode
	}
	return ""
}

// --- CORS (shared/cors.js) ------------------------------------------------------------------------------------------

type corsPolicy struct {
	methods     string
	clientBased bool
	expose      func(oc *oidcCtx) string
}

func (p *Provider) exposeHeaders(dpop, wwwAuth bool) func(oc *oidcCtx) string {
	return func(oc *oidcCtx) string {
		var headers []string
		if dpop && p.dpopNonces != nil {
			headers = append(headers, "DPoP-Nonce")
		}
		if wwwAuth {
			headers = append(headers, "WWW-Authenticate")
		}
		return strings.Join(headers, ",")
	}
}

// cors applies the CORS middleware; it answers preflights (done true).
func (oc *oidcCtx) cors(policy corsPolicy) (done bool) {
	oc.vary("Origin")
	origin := oc.r.Header.Get("origin")
	if oc.method != http.MethodOptions {
		if origin == "" {
			origin = "*"
		}
		oc.header.Set("Access-Control-Allow-Origin", origin)
		if policy.expose != nil {
			if headers := policy.expose(oc); headers != "" {
				oc.header.Set("Access-Control-Expose-Headers", headers)
			}
		}
		if policy.clientBased && oc.r.Header.Get("origin") != "" {
			oc.corsClientBased = true
		}
		return false
	}
	if oc.r.Header.Get("access-control-request-method") == "" {
		return false
	}
	if origin == "" {
		origin = "*"
	}
	oc.header.Set("Access-Control-Allow-Origin", origin)
	oc.header.Set("Access-Control-Max-Age", "3600")
	oc.header.Set("Access-Control-Allow-Methods", policy.methods)
	if requested := oc.r.Header.Get("access-control-request-headers"); requested != "" {
		oc.header.Set("Access-Control-Allow-Headers", requested)
	}
	oc.setStatus(204)
	return true
}

func (oc *oidcCtx) vary(field string) {
	for _, existing := range oc.header.Values("Vary") {
		if strings.EqualFold(existing, field) {
			return
		}
	}
	oc.header.Add("Vary", field)
}

// assignClient sets the request's client, running the client-based CORS check (clientBasedCORS).
func (oc *oidcCtx) assignClient(client *oidcClient) error {
	oc.client = client
	if oc.corsClientBased && client != nil {
		origin := oc.r.Header.Get("origin")
		allowed := false
		for _, uri := range client.redirectURIs() {
			if parsed, err := parseURL(uri); err == nil && urlOrigin(parsed) == origin {
				allowed = true
			}
		}
		if !allowed {
			oc.header.Del("Access-Control-Allow-Origin")
			return errInvalidRequest("origin " + origin + " not allowed for client: " + client.clientID())
		}
	}
	return nil
}

// --- the mount and router -------------------------------------------------------------------------------------------

// fold is the router's case folding.
func fold(value string) string { return strings.ToUpper(value) }

type routeMatch struct {
	name   string
	params map[string]string
}

var routeTable = []struct {
	method, name, path string
}{
	{"GET", "authorization", "/auth"},
	{"GET", "resume", "/auth/:uid"},
	{"GET", "userinfo", "/me"},
	{"POST", "userinfo", "/me"},
	{"OPTIONS", "cors.userinfo", "/me"},
	{"POST", "token", "/token"},
	{"OPTIONS", "cors.token", "/token"},
	{"GET", "jwks", "/jwks"},
	{"OPTIONS", "cors.jwks", "/jwks"},
	{"GET", "discovery", "/.well-known/oauth-authorization-server"},
	{"OPTIONS", "cors.discovery", "/.well-known/oauth-authorization-server"},
	{"GET", "discovery", "/.well-known/openid-configuration"},
	{"OPTIONS", "cors.discovery", "/.well-known/openid-configuration"},
	{"POST", "registration", "/reg"},
	{"GET", "client", "/reg/:clientId"},
	{"POST", "revocation", "/token/revocation"},
	{"OPTIONS", "cors.revocation", "/token/revocation"},
	{"POST", "introspection", "/token/introspection"},
	{"OPTIONS", "cors.introspection", "/token/introspection"},
	{"POST", "end_session_confirm", "/session/end/confirm"},
	{"GET", "end_session", "/session/end"},
	{"GET", "end_session_success", "/session/end/success"},
	{"POST", "device_authorization", "/device/auth"},
	{"OPTIONS", "cors.device_authorization", "/device/auth"},
	{"GET", "code_verification", "/device"},
	{"POST", "code_verification", "/device"},
	{"GET", "device_resume", "/device/:uid"},
	{"POST", "pushed_authorization_request", "/request"},
	{"OPTIONS", "cors.pushed_authorization_request", "/request"},
}

func (p *Provider) lookup(method, path string) *routeMatch {
	if method == http.MethodHead {
		method = http.MethodGet
	}
	folded := fold(path)
	for _, route := range routeTable {
		if route.method != method || strings.Contains(route.path, "/:") {
			continue
		}
		if route.name == "registration" || route.name == "client" {
			if p.config.Registration == nil {
				continue
			}
		}
		if fold(route.path) == folded {
			return &routeMatch{name: route.name, params: map[string]string{}}
		}
	}
	parts := strings.Split(path, "/")
	foldedParts := strings.Split(folded, "/")
	for _, route := range routeTable {
		if route.method != method || !strings.Contains(route.path, "/:") {
			continue
		}
		if route.name == "client" && p.config.Registration == nil {
			continue
		}
		segments := strings.Split(route.path, "/")
		if len(segments) != len(parts) {
			continue
		}
		params := map[string]string{}
		matched := true
		for index, segment := range segments {
			if strings.HasPrefix(segment, ":") {
				if parts[index] == "" {
					matched = false
					break
				}
				value, ok := decodeURIComponent(parts[index])
				if !ok {
					value = parts[index]
				}
				params[segment[1:]] = value
			} else if fold(segment) != foldedParts[index] {
				matched = false
				break
			}
		}
		if matched {
			return &routeMatch{name: route.name, params: params}
		}
	}
	return nil
}

func (p *Provider) match(method, path string) *routeMatch {
	if found := p.lookup(method, path); found != nil {
		return found
	}
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		return p.lookup(method, path[:len(path)-1])
	}
	return nil
}

// Handler is the complete provider mount (nodeHandler): it serves the provider's routes under the issuer path and,
// for an issuer with a path, the RFC 8414 discovery document at `/.well-known/oauth-authorization-server{path}`.
func (p *Provider) Handler(w http.ResponseWriter, r *http.Request) {
	originalURL := r.URL.RequestURI()
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	oauthDiscovery := "/.well-known/oauth-authorization-server" + p.BasePath
	routed := path
	if path == oauthDiscovery {
		routed = "/.well-known/oauth-authorization-server"
	} else if p.BasePath != "" && strings.HasPrefix(path, p.BasePath+"/") {
		routed = path[len(p.BasePath):]
	}
	oc := &oidcCtx{p: p, ctx: r.Context(), r: r, method: r.Method, path: routed, originalURL: originalURL,
		header: http.Header{}, query: queryParse(r.URL.RawQuery)}
	if path == oauthDiscovery {
		// urlFor derives the mount from the original URL, which here does not end with the routed path.
		oc.originalURL = originalURL
	}
	if p.config.Registration != nil && r.Method == http.MethodPost && isRegistrationPath(routed) {
		done, err := p.registrationGate(oc)
		if err != nil {
			status, text := 500, "Internal Server Error"
			var iam *core.IamError
			if errors.As(err, &iam) && http.StatusText(iam.Status) != "" {
				status, text = iam.Status, http.StatusText(iam.Status)
			}
			oc.header = http.Header{}
			oc.setStatus(status)
			oc.respBody, oc.contentType = text, "text/plain; charset=utf-8"
			oc.write(w)
			return
		}
		if done {
			oc.write(w)
			return
		}
	}
	match := p.match(r.Method, routed)
	if match == nil {
		oc.write(w)
		return
	}
	oc.route = match.name
	oc.routeParams = match.params
	p.dispatch(oc)
	oc.write(w)
}

// ServeHTTP makes the provider an http.Handler.
func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) { p.Handler(w, r) }

func (p *Provider) dispatch(oc *oidcCtx) {
	defer func() {
		if recovered := recover(); recovered != nil {
			oc.header = http.Header{}
			oc.setCookies = nil
			oc.location = ""
			oc.setStatus(500)
			oc.setJSON(outObject(errOut(errors.New("panic"), "", false)))
		}
	}()
	var err error
	switch oc.route {
	case "authorization", "resume":
		err = p.authorizationEndpoint(oc)
	case "userinfo":
		if oc.cors(corsPolicy{methods: "GET,POST", clientBased: true, expose: p.exposeHeaders(true, true)}) {
			return
		}
		err = p.guard(oc, p.userinfoEndpoint)
	case "token":
		err = p.guard(oc, func(oc *oidcCtx) error {
			if oc.cors(corsPolicy{methods: "POST", clientBased: true, expose: p.exposeHeaders(true, true)}) {
				return nil
			}
			return p.tokenEndpoint(oc)
		})
	case "jwks":
		oc.cors(corsPolicy{methods: "GET"})
		err = p.guard(oc, func(oc *oidcCtx) error {
			oc.setJSON(p.keys.public)
			oc.contentType = "application/jwk-set+json; charset=utf-8"
			return nil
		})
	case "discovery":
		oc.cors(corsPolicy{methods: "GET"})
		err = p.guard(oc, func(oc *oidcCtx) error {
			oc.setJSON(p.discovery(oc))
			return nil
		})
	case "registration":
		err = p.guard(oc, p.registrationEndpoint)
	case "client":
		err = p.guard(oc, p.clientReadEndpoint)
	case "revocation":
		err = p.guard(oc, func(oc *oidcCtx) error {
			if oc.cors(corsPolicy{methods: "POST", clientBased: true, expose: p.exposeHeaders(false, true)}) {
				return nil
			}
			return p.revocationEndpoint(oc)
		})
	case "introspection":
		err = p.guard(oc, func(oc *oidcCtx) error {
			if oc.cors(corsPolicy{methods: "POST", clientBased: true, expose: p.exposeHeaders(false, true)}) {
				return nil
			}
			return p.introspectionEndpoint(oc)
		})
	case "end_session_confirm":
		err = p.guard(oc, p.endSessionConfirm)
	case "end_session":
		err = p.guard(oc, p.endSessionInit)
	case "end_session_success":
		err = p.guard(oc, p.endSessionSuccess)
	case "device_authorization":
		err = p.guard(oc, func(oc *oidcCtx) error {
			if oc.cors(corsPolicy{methods: "POST", clientBased: true, expose: p.exposeHeaders(false, true)}) {
				return nil
			}
			return p.deviceAuthorizationEndpoint(oc)
		})
	case "code_verification":
		err = p.guard(oc, p.codeVerificationEndpoint)
	case "device_resume":
		err = p.guard(oc, p.deviceResumeEndpoint)
	case "pushed_authorization_request":
		err = p.guard(oc, func(oc *oidcCtx) error {
			if oc.cors(corsPolicy{methods: "POST", clientBased: true, expose: p.exposeHeaders(true, true)}) {
				return nil
			}
			return p.parEndpoint(oc)
		})
	default:
		if strings.HasPrefix(oc.route, "cors.") {
			policy := corsPolicy{methods: "POST", clientBased: true}
			switch oc.route {
			case "cors.userinfo":
				policy.methods = "GET,POST"
			case "cors.jwks", "cors.discovery":
				policy = corsPolicy{methods: "GET"}
			}
			oc.cors(policy)
		}
	}
	if err == nil && oc.session != nil {
		err = p.ensureSessionSave(oc)
	}
	if err != nil {
		oc.setStatus(500)
		oc.setJSON(outObject(errOut(err, "", false)))
	}
}

// guard runs a route under the generic error handler, then persists a touched session (ensureSessionSave).
func (p *Provider) guard(oc *oidcCtx, route func(oc *oidcCtx) error) error {
	if err := route(oc); err != nil {
		if errors.Is(err, errInsecureCookie) {
			return err
		}
		oc.handleError(err)
	}
	return nil
}

// ensureSessionSave persists a session the route touched.
func (p *Provider) ensureSessionSave(oc *oidcCtx) error {
	if oc.session != nil && oc.session.touched && !oc.session.destroyed {
		exp, _ := oc.session.data.Get("exp").(float64)
		if exp == 0 {
			return nil
		}
		return p.saveSession(oc, int64(exp)-epoch(p.now()))
	}
	return nil
}

func (p *Provider) saveSession(oc *oidcCtx, ttl int64) error {
	session := oc.session
	if session.oldID != "" {
		if err := p.adapter.Model("Session").Destroy(oc.ctx, session.oldID); err != nil {
			return err
		}
		session.oldID = ""
	}
	if _, err := p.save(oc.ctx, oc, session, ttl); err != nil {
		return err
	}
	session.touched = false
	return nil
}

// loadSession is shared/session.js's entry: the session of the `_session` cookie (or a new one).
func (p *Provider) loadSession(oc *oidcCtx) error {
	cookieID := oc.getCookie("_session")
	var session *model
	if cookieID != "" {
		found, err := p.find(oc.ctx, "Session", cookieID, false)
		if err != nil {
			return err
		}
		session = found
	}
	if session == nil {
		session = newSession()
		if cookieID != "" {
			session.isNew = false
		}
	}
	oc.session = session
	return nil
}

// finishSession is shared/session.js's finally: persist the session and set its cookie.
func (p *Provider) finishSession(oc *oidcCtx) error {
	session := oc.session
	if session == nil {
		return nil
	}
	if (!session.isNew || session.touched) && !session.destroyed {
		if err := oc.setCookie("_session", session.jti(), p.longCookie()); err != nil {
			return err
		}
		if err := p.saveSession(oc, 86400); err != nil {
			return err
		}
	}
	exp, _ := session.data.Get("exp").(float64)
	if exp != 0 && session.data.Get("transient") != true {
		expires := time.UnixMilli(int64(exp) * 1000).UTC().Format(http.TimeFormat)
		for index, cookie := range oc.setCookies {
			if (strings.HasPrefix(cookie, "_session=") || strings.HasPrefix(cookie, "_session.sig=")) && !strings.Contains(cookie, "expires=Thu, 01 Jan 1970") {
				oc.setCookies[index] = cookie + "; expires=" + expires
			}
		}
	}
	return nil
}

// generateXsrf is shared/xsrf.js generateXsrf.
func (oc *oidcCtx) generateXsrf() {
	sessionSet(oc.session, "state", core.NewObject("secret", randomHex(24)))
}

// checkXsrf is shared/xsrf.js checkXsrf.
func (oc *oidcCtx) checkXsrf(missing string) error {
	state := obj(oc.session.data, "state")
	if state == nil {
		return errInvalidRequest(missing)
	}
	if !constantEquals(str(state, "secret"), oc.param("xsrf")) {
		return errInvalidRequest("xsrf token invalid")
	}
	return nil
}

// noCache is shared/no_cache.js.
func (oc *oidcCtx) noCache() { oc.header.Set("cache-control", "no-store") }

// formPost is response_modes/form_post.js.
func (oc *oidcCtx) formPost(action string, inputs [][2]string) {
	hasError := false
	var fields []string
	for _, pair := range inputs {
		if pair[0] == "error" {
			hasError = true
		}
		fields = append(fields, `<input type="hidden" name="`+pair[0]+`" value="`+htmlSafe(pair[1])+`"/>`)
	}
	if !oc.statusSet || (oc.status != 200 && oc.status != 400 && oc.status != 500) {
		if hasError {
			oc.setStatus(400)
		} else {
			oc.setStatus(200)
		}
	}
	oc.setHTML(`<!DOCTYPE html>
<html>
<head>
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>Submitting Callback</title>
  <script>
    document.addEventListener('DOMContentLoaded', function () { document.forms[0].submit() });
  </script>
</head>
<body>
  <form method="post" action="` + htmlSafe(action) + `">
    ` + strings.Join(fields, "\n") + `
    <noscript>
      Your browser does not support JavaScript or you've disabled it.<br/>
      <button autofocus type="submit">Continue</button>
    </noscript>
  </form>
</body>
</html>`)
}

// discovery is actions/discovery.js.
func (p *Provider) discovery(oc *oidcCtx) *core.Object {
	body := core.NewObject(
		"authorization_endpoint", oc.urlFor("authorization", nil, nil),
		"device_authorization_endpoint", oc.urlFor("device_authorization", nil, nil),
		"claims_parameter_supported", false,
		"claims_supported", anyList(p.claimsSupported),
		"code_challenge_methods_supported", []any{"S256"},
		"end_session_endpoint", oc.urlFor("end_session", nil, nil),
		"grant_types_supported", anyList(p.grantTypes),
		"issuer", p.issuer,
		"jwks_uri", oc.urlFor("jwks", nil, nil),
	)
	if p.config.Registration != nil {
		body.Set("registration_endpoint", oc.urlFor("registration", nil, nil))
	}
	body.Set("authorization_response_iss_parameter_supported", true)
	body.Set("response_modes_supported", []any{"form_post", "fragment", "query"})
	body.Set("response_types_supported", []any{"code"})
	body.Set("scopes_supported", anyList(p.supportedScopes))
	body.Set("subject_types_supported", []any{"public"})
	body.Set("token_endpoint_auth_methods_supported", anyList(clientAuthMethods))
	body.Set("token_endpoint_auth_signing_alg_values_supported", anyList(clientAuthAlgs))
	body.Set("token_endpoint", oc.urlFor("token", nil, nil))
	body.Set("id_token_signing_alg_values_supported", anyList(p.keys.idTokenAlgs))
	body.Set("pushed_authorization_request_endpoint", oc.urlFor("pushed_authorization_request", nil, nil))
	if p.config.RequirePushedAuthorizationRequests {
		body.Set("require_pushed_authorization_requests", true)
	}
	body.Set("request_uri_parameter_supported", false)
	body.Set("userinfo_endpoint", oc.urlFor("userinfo", nil, nil))
	body.Set("introspection_endpoint", oc.urlFor("introspection", nil, nil))
	body.Set("dpop_signing_alg_values_supported", anyList(dpopSigningAlgs))
	body.Set("revocation_endpoint", oc.urlFor("revocation", nil, nil))
	body.Set("backchannel_logout_supported", true)
	body.Set("backchannel_logout_session_supported", true)
	body.Set("claim_types_supported", []any{"normal"})
	return body
}
