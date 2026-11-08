package oauth

// Port of packages/oauth/src/resource-server.ts: offline verification of JWT access tokens issued for a resource
// server (RFC 9068), DPoP proof of possession (RFC 9449), RFC 9728 protected resource metadata, and a resource
// guard for APIs such as MCP servers.

import (
	"container/list"
	"context"
	"errors"
	"math"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Better-IAM/better-iam/go/core"
)

// AccessTokenVerifierOptions are createAccessTokenVerifier's options.
type AccessTokenVerifierOptions struct {
	// Issuer is the authorization server issuer, exactly as in its discovery document.
	Issuer string
	// Audience lists the `aud` values this API accepts.
	Audience []string
	// JWKS are the public signing keys; without them `{issuer}/jwks` (or JWKSURI) is fetched and cached.
	JWKS    any
	JWKSURI string
	// ClockTolerance is the seconds of skew tolerated for exp, nbf and DPoP iat (default 30).
	ClockTolerance *float64
	// DPoPMaxAge is the maximum age of a DPoP proof in seconds (default 300).
	DPoPMaxAge *float64
	// Algorithms accepted for access tokens (default the asymmetric JOSE algorithms).
	Algorithms []string
	// TenantID refuses tokens of every other organization when set.
	TenantID *string
	// Now overrides the clock (epoch milliseconds).
	Now func() int64
	// HTTPClient fetches a remote JWKS (default http.DefaultClient).
	HTTPClient *http.Client
}

// ProtectedRequest is the request parts a DPoP-aware API check needs.
type ProtectedRequest struct {
	// Authorization is the `Authorization` header: `Bearer <token>` or `DPoP <token>`.
	Authorization string
	// DPoP is the `DPoP` proof header, required with the DPoP scheme.
	DPoP   string
	Method string
	// URL is the absolute request URL; query and fragment are ignored for `htu`.
	URL string
}

// VerifiedAccessToken is a verified access token.
type VerifiedAccessToken struct {
	// Subject is the account, or the client for client-credentials tokens ("" when absent).
	Subject    string
	ClientID   string
	TenantID   string
	IdentityID string
	Scopes     []string
	Audience   []string
	IssuedAt   *float64
	ExpiresAt  float64
	TokenID    string
	// BoundKey is the JWK SHA-256 thumbprint the token is bound to (DPoP).
	BoundKey string
	// Actor is the delegation chain of an exchanged token (RFC 8693 `act`), nil when absent.
	Actor  *core.Object
	Claims *core.Object
}

var asymmetricAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "Ed25519"}

func challengeAlgorithms() []string {
	out := []string{}
	for _, alg := range asymmetricAlgorithms {
		if alg != "Ed25519" {
			out = append(out, alg)
		}
	}
	return out
}

func invalidToken(message string) *core.IamError {
	return core.NewIamError("INVALID_TOKEN", message, 401)
}

func targetURI(value string) (string, error) {
	parsed, err := parseURL(value)
	if err != nil {
		return "", err
	}
	return withoutSearchAndHash(parsed), nil
}

// AccessTokenVerifier verifies access tokens offline.
type AccessTokenVerifier struct {
	issuers        []string
	audience       []string
	resolve        joseResolver
	clockTolerance float64
	dpopMaxAge     float64
	algorithms     []string
	tenantID       *string
	now            func() int64

	mu         sync.Mutex
	seenProofs map[string]*list.Element
	order      *list.List
}

type seenProof struct {
	key     string
	expires float64
}

// CreateAccessTokenVerifier is createAccessTokenVerifier.
func CreateAccessTokenVerifier(options AccessTokenVerifierOptions) (*AccessTokenVerifier, error) {
	issuer := strings.TrimSuffix(options.Issuer, "/")
	// The provider writes `iss` exactly as its issuer is configured, trailing slash included; both are accepted.
	issuers := unique([]string{options.Issuer, issuer})
	v := &AccessTokenVerifier{issuers: issuers, audience: options.Audience, clockTolerance: 30, dpopMaxAge: 300,
		algorithms: asymmetricAlgorithms, tenantID: options.TenantID, now: options.Now,
		seenProofs: map[string]*list.Element{}, order: list.New()}
	if v.now == nil {
		v.now = wallNow
	}
	if options.ClockTolerance != nil {
		v.clockTolerance = *options.ClockTolerance
	}
	if options.DPoPMaxAge != nil {
		v.dpopMaxAge = *options.DPoPMaxAge
	}
	if options.Algorithms != nil {
		v.algorithms = options.Algorithms
	}
	if options.JWKS != nil {
		set, err := joseNewLocalSet(core.Normalize(options.JWKS))
		if err != nil {
			return nil, err
		}
		v.resolve = set.resolve
	} else {
		uri := options.JWKSURI
		if uri == "" {
			uri = issuer + "/jwks"
		}
		parsed, err := parseURL(uri)
		if err != nil {
			return nil, &core.TypeError{Message: "Invalid URL"}
		}
		client := options.HTTPClient
		if client == nil {
			client = http.DefaultClient
		}
		remote := &joseRemoteSet{href: parsed.Href, timeout: 5 * time.Second, cooldownDuration: 30000, cacheMaxAge: 600000, client: client}
		v.resolve = remote.resolve
	}
	return v, nil
}

// rememberProof refuses a proof seen before, remembering each one until it can no longer be accepted.
func (v *AccessTokenVerifier) rememberProof(jti, keyThumbprint string, issuedAt float64) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := float64(v.now())
	for front := v.order.Front(); front != nil; front = v.order.Front() {
		entry := front.Value.(*seenProof)
		if entry.expires > now {
			break
		}
		v.order.Remove(front)
		delete(v.seenProofs, entry.key)
	}
	key := keyThumbprint + ":" + jti
	if element, ok := v.seenProofs[key]; ok {
		if element.Value.(*seenProof).expires > now {
			return invalidToken("DPoP proof was already used.")
		}
		v.order.Remove(element)
		delete(v.seenProofs, key)
	}
	until := math.Max(now, issuedAt*1000) + (v.dpopMaxAge+v.clockTolerance)*1000
	v.seenProofs[key] = v.order.PushBack(&seenProof{key: key, expires: until})
	return nil
}

func (v *AccessTokenVerifier) verifyToken(ctx context.Context, token string) (*VerifiedAccessToken, error) {
	payload, _, err := joseJwtVerify(ctx, token, v.resolve, joseVerifyOptions{
		hasIssuer: true, issuer: v.issuers[0], issuers: v.issuers, audience: v.audience, typ: "at+jwt",
		clockTolerance: v.clockTolerance, algorithms: v.algorithms, requiredClaims: []string{"exp", "client_id"},
		currentDate: float64(v.now()), maxTokenAge: core.Undefined,
	})
	if err != nil {
		return nil, invalidToken("The access token is invalid or expired.")
	}
	if v.tenantID != nil && !jsEq(payload.Get("tenant_id"), *v.tenantID) {
		return nil, invalidToken("The access token was issued for another organization.")
	}
	verified := &VerifiedAccessToken{ClientID: jsString(payload.Get("client_id")), Claims: payload, Scopes: []string{}, Audience: []string{}}
	verified.Subject, _ = payload.Get("sub").(string)
	verified.TenantID, _ = payload.Get("tenant_id").(string)
	verified.IdentityID, _ = payload.Get("identity_id").(string)
	if scope, ok := payload.Get("scope").(string); ok {
		verified.Scopes = splitFilter(scope)
	}
	switch aud := payload.Get("aud").(type) {
	case []any:
		verified.Audience = stringList(aud)
	case string:
		if aud != "" {
			verified.Audience = []string{aud}
		}
	}
	if iat, ok := payload.Get("iat").(float64); ok {
		verified.IssuedAt = &iat
	}
	verified.ExpiresAt, _ = payload.Get("exp").(float64)
	verified.TokenID, _ = payload.Get("jti").(string)
	if cnf := obj(payload, "cnf"); cnf != nil {
		verified.BoundKey, _ = cnf.Get("jkt").(string)
	}
	if act := obj(payload, "act"); act != nil {
		if _, ok := act.Get("sub").(string); ok {
			verified.Actor = act
		}
	}
	return verified, nil
}

func (v *AccessTokenVerifier) verifyProof(ctx context.Context, proof, token string, request ProtectedRequest, boundKey string) error {
	header, err := joseDecodeProtectedHeader(proof)
	var jwk *core.Object
	var payload *core.Object
	if err == nil {
		jwk, _ = header.Get("jwk").(*core.Object)
		payload, _, err = joseJwtVerify(ctx, proof, joseEmbeddedJWK, joseVerifyOptions{
			typ: "dpop+jwt", algorithms: asymmetricAlgorithms, maxTokenAge: v.dpopMaxAge, clockTolerance: v.clockTolerance,
			requiredClaims: []string{"iat", "jti", "htm", "htu", "ath"}, currentDate: float64(v.now()),
		})
	}
	if err != nil {
		return invalidToken("The DPoP proof is invalid.")
	}
	thumbprint := ""
	if jwk != nil {
		thumbprint, _ = joseThumbprint(jwk)
	}
	if jwk == nil || thumbprint != boundKey {
		return invalidToken("The DPoP proof key does not match the token binding.")
	}
	htu, err := targetURI(jsString(payload.Get("htu")))
	if err != nil {
		return invalidToken("The DPoP proof target is invalid.")
	}
	requestTarget, err := targetURI(request.URL)
	if !jsEq(payload.Get("htm"), strings.ToUpper(request.Method)) || err != nil || htu != requestTarget ||
		!jsEq(payload.Get("ath"), sha256B64URL(token)) {
		return invalidToken("The DPoP proof does not match this request.")
	}
	iat, _ := payload.Get("iat").(float64)
	if _, isNumber := payload.Get("iat").(float64); !isNumber {
		iat = math.NaN()
	}
	return v.rememberProof(jsString(payload.Get("jti")), boundKey, iat)
}

func requireScopes(verified *VerifiedAccessToken, scopes []string) error {
	var missing []string
	for _, scope := range scopes {
		if !contains(verified.Scopes, scope) {
			missing = append(missing, scope)
		}
	}
	if len(missing) > 0 {
		return core.NewIamError("INSUFFICIENT_SCOPE", "Missing scope: "+strings.Join(missing, " ")+".", 403)
	}
	return nil
}

// Verify verifies a bearer access token string; DPoP-bound tokens are refused here (use VerifyRequest).
func (v *AccessTokenVerifier) Verify(ctx context.Context, token string, scopes []string) (*VerifiedAccessToken, error) {
	verified, err := v.verifyToken(ctx, token)
	if err != nil {
		return nil, err
	}
	if verified.BoundKey != "" {
		return nil, invalidToken("A DPoP-bound token requires a DPoP proof.")
	}
	if err := requireScopes(verified, scopes); err != nil {
		return nil, err
	}
	return verified, nil
}

var authorizationPattern = regexp.MustCompile(`(?i)^(Bearer|DPoP) ([A-Za-z0-9._~+/-]+=*)$`)

// VerifyRequest verifies the Authorization header of a request, checking the DPoP proof when the token is bound.
func (v *AccessTokenVerifier) VerifyRequest(ctx context.Context, request ProtectedRequest, scopes []string) (*VerifiedAccessToken, error) {
	match := authorizationPattern.FindStringSubmatch(request.Authorization)
	if match == nil {
		return nil, invalidToken("An access token is required.")
	}
	scheme := strings.ToLower(match[1])
	token := match[2]
	verified, err := v.verifyToken(ctx, token)
	if err != nil {
		return nil, err
	}
	if verified.BoundKey != "" {
		if scheme != "dpop" || request.DPoP == "" {
			return nil, invalidToken("A DPoP-bound token requires the DPoP scheme and proof.")
		}
		if err := v.verifyProof(ctx, request.DPoP, token, request, verified.BoundKey); err != nil {
			return nil, err
		}
	} else if scheme == "dpop" {
		return nil, invalidToken("The access token is not DPoP-bound.")
	}
	if err := requireScopes(verified, scopes); err != nil {
		return nil, err
	}
	return verified, nil
}

func challengeQuote(value string) string { return strings.NewReplacer(`"`, "", `\`, "").Replace(value) }

// Challenge is a `WWW-Authenticate` challenge for a failed verification.
func (v *AccessTokenVerifier) Challenge(err error, realm, resourceMetadata string, scopes []string) string {
	code := "invalid_token"
	var iam *core.IamError
	if errors.As(err, &iam) && iam.Code == "INSUFFICIENT_SCOPE" {
		code = "insufficient_scope"
	}
	shared := []string{}
	if realm != "" {
		shared = append(shared, `realm="`+challengeQuote(realm)+`"`)
	}
	shared = append(shared, `error="`+code+`"`)
	if resourceMetadata != "" {
		shared = append(shared, `resource_metadata="`+challengeQuote(resourceMetadata)+`"`)
	}
	if code == "insufficient_scope" && len(scopes) > 0 {
		shared = append(shared, `scope="`+challengeQuote(strings.Join(scopes, " "))+`"`)
	}
	algs := `algs="` + strings.Join(challengeAlgorithms(), " ") + `"`
	return "DPoP " + strings.Join(append(append([]string{}, shared...), algs), ", ") + ", Bearer " + strings.Join(shared, ", ")
}

// ProtectedResourceMetadataOptions describe one API (RFC 9728).
type ProtectedResourceMetadataOptions struct {
	// Resource is the API's resource identifier: the resource indicator its access tokens are issued for.
	Resource string
	// AuthorizationServers are the issuer URLs of the authorization servers that issue tokens for it.
	AuthorizationServers []string
	Scopes               []string
	ResourceName         string
	// Documentation is a page describing the API for developers.
	Documentation string
	// RequireDPoP advertises that only DPoP-bound access tokens are accepted.
	RequireDPoP bool
}

func absoluteURL(value, label string) (*parsedURL, error) {
	parsed, err := parseURL(value)
	if err != nil {
		return nil, core.NewIamError("configuration", label+" must be an absolute URL.")
	}
	if urlHasHash(parsed) || urlHasCredentials(parsed) {
		return nil, core.NewIamError("configuration", label+" cannot carry a fragment or credentials.")
	}
	return parsed, nil
}

// ProtectedResourceMetadata is the metadata document (RFC 9728 §2).
func ProtectedResourceMetadata(options ProtectedResourceMetadataOptions) (*core.Object, error) {
	if _, err := absoluteURL(options.Resource, "The resource"); err != nil {
		return nil, err
	}
	if len(options.AuthorizationServers) == 0 {
		return nil, core.NewIamError("configuration", "At least one authorization server is required.")
	}
	for _, server := range options.AuthorizationServers {
		if _, err := absoluteURL(server, "An authorization server"); err != nil {
			return nil, err
		}
	}
	document := core.NewObject("resource", options.Resource, "authorization_servers", anyList(options.AuthorizationServers))
	if len(options.Scopes) > 0 {
		document.Set("scopes_supported", anyList(options.Scopes))
	}
	document.Set("bearer_methods_supported", []any{"header"})
	if options.ResourceName != "" {
		document.Set("resource_name", options.ResourceName)
	}
	if options.Documentation != "" {
		document.Set("resource_documentation", options.Documentation)
	}
	document.Set("dpop_signing_alg_values_supported", anyList(challengeAlgorithms()))
	if options.RequireDPoP {
		document.Set("dpop_bound_access_tokens_required", true)
	}
	return document, nil
}

// ProtectedResourceMetadataURL is where the metadata lives: `/.well-known/oauth-protected-resource` inserted
// before the resource's path.
func ProtectedResourceMetadataURL(resource string) (string, error) {
	parsed, err := absoluteURL(resource, "The resource")
	if err != nil {
		return "", err
	}
	path := urlPathname(parsed)
	if path == "/" {
		path = ""
	} else {
		path = strings.TrimSuffix(path, "/")
	}
	return urlOrigin(parsed) + "/.well-known/oauth-protected-resource" + path, nil
}

// ProtectedResourceHandler serves the metadata document; nil for every other request.
type ProtectedResourceHandler func(request *http.Request) *Response

// CreateProtectedResourceHandler serves the metadata document at its well-known path (GET, HEAD, and CORS preflight,
// readable from any origin).
func CreateProtectedResourceHandler(options ProtectedResourceMetadataOptions) (ProtectedResourceHandler, error) {
	metadata, err := ProtectedResourceMetadata(options)
	if err != nil {
		return nil, err
	}
	document := stringify(metadata)
	metadataURL, err := ProtectedResourceMetadataURL(options.Resource)
	if err != nil {
		return nil, err
	}
	parsed, _ := parseURL(metadataURL)
	path := urlPathname(parsed)
	return func(request *http.Request) *Response {
		if request.URL.EscapedPath() != path {
			return nil
		}
		header := http.Header{}
		header.Set("access-control-allow-origin", "*")
		header.Set("access-control-allow-methods", "GET, HEAD, OPTIONS")
		if request.Method == http.MethodOptions {
			return &Response{Status: 204, Header: header}
		}
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			header.Set("allow", "GET, HEAD, OPTIONS")
			return &Response{Status: 405, Header: header}
		}
		header.Set("content-type", "application/json")
		header.Set("cache-control", "public, max-age=3600")
		if request.Method == http.MethodHead {
			return &Response{Status: 200, Header: header}
		}
		return &Response{Status: 200, Header: header, Body: []byte(document)}
	}, nil
}

// ResourceGuardOptions configure a resource guard.
type ResourceGuardOptions struct {
	ProtectedResourceMetadataOptions
	// Issuer is the token issuer to trust; defaults to the first authorization server.
	Issuer string
	// Audience lists the accepted `aud` values; defaults to the resource identifier.
	Audience       []string
	JWKS           any
	JWKSURI        string
	ClockTolerance *float64
	// RequiredScopes are the scopes every request needs; Check adds per-route scopes.
	RequiredScopes []string
	Realm          string
	// TenantID refuses tokens of every other organization.
	TenantID *string
	Now      func() int64
}

// ResourceGuard serves the RFC 9728 metadata, verifies bearer or DPoP access tokens, and answers failures with a
// `WWW-Authenticate` challenge naming the metadata URL.
type ResourceGuard struct {
	MetadataURL string
	Verifier    *AccessTokenVerifier
	metadata    ProtectedResourceHandler
	options     ResourceGuardOptions
}

// CreateResourceGuard is createResourceGuard.
func CreateResourceGuard(options ResourceGuardOptions) (*ResourceGuard, error) {
	metadata, err := CreateProtectedResourceHandler(options.ProtectedResourceMetadataOptions)
	if err != nil {
		return nil, err
	}
	metadataURL, _ := ProtectedResourceMetadataURL(options.Resource)
	issuer := options.Issuer
	if issuer == "" {
		issuer = options.AuthorizationServers[0]
	}
	audience := options.Audience
	if audience == nil {
		audience = []string{options.Resource}
	}
	verifier, err := CreateAccessTokenVerifier(AccessTokenVerifierOptions{Issuer: issuer, Audience: audience,
		JWKS: options.JWKS, JWKSURI: options.JWKSURI, ClockTolerance: options.ClockTolerance, TenantID: options.TenantID, Now: options.Now})
	if err != nil {
		return nil, err
	}
	return &ResourceGuard{MetadataURL: metadataURL, Verifier: verifier, metadata: metadata, options: options}, nil
}

// Check answers the metadata document or a refusal (response set), or the verified token of an authorized request.
func (g *ResourceGuard) Check(ctx context.Context, request *http.Request, scopes []string) (*Response, *VerifiedAccessToken, error) {
	if served := g.metadata(request); served != nil {
		return served, nil, nil
	}
	required := unique(append(append([]string{}, g.options.RequiredScopes...), scopes...))
	authorization := request.Header.Get("authorization")
	if authorization == "" {
		// RFC 6750 §3.1: no error code when the request carried no credentials at all.
		parts := []string{}
		if g.options.Realm != "" {
			parts = append(parts, `realm="`+challengeQuote(g.options.Realm)+`"`)
		}
		parts = append(parts, `resource_metadata="`+challengeQuote(g.MetadataURL)+`"`)
		if len(required) > 0 {
			parts = append(parts, `scope="`+challengeQuote(strings.Join(required, " "))+`"`)
		}
		header := http.Header{}
		header.Set("cache-control", "no-store")
		header.Set("www-authenticate", "Bearer "+strings.Join(parts, ", "))
		return &Response{Status: 401, Header: header}, nil, nil
	}
	token, err := g.Verifier.VerifyRequest(ctx, ProtectedRequest{Authorization: authorization, DPoP: request.Header.Get("dpop"),
		Method: request.Method, URL: requestURL(request)}, required)
	if err != nil {
		var iam *core.IamError
		if !errors.As(err, &iam) {
			return nil, nil, err
		}
		insufficient := iam.Code == "INSUFFICIENT_SCOPE"
		code, status := "invalid_token", 401
		if insufficient {
			code, status = "insufficient_scope", 403
		}
		return jsonResponse(status, core.NewObject("error", code, "error_description", iam.Message), map[string]string{
			"cache-control":    "no-store",
			"www-authenticate": g.Verifier.Challenge(err, g.options.Realm, g.MetadataURL, required),
		}), nil, nil
	}
	return nil, token, nil
}

// requestURL is the absolute URL of an incoming request (Request#url).
func requestURL(request *http.Request) string {
	if request.URL.IsAbs() {
		return request.URL.String()
	}
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + request.Host + request.URL.RequestURI()
}
