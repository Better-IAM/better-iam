package oauth

// Port of packages/oauth/src/client.ts: OAuth/OIDC relying-party flows (sign in with Google, GitHub, Entra ID, any
// OIDC provider or a generic OAuth2 provider). Login state is single-use, browser-bound and tenant-bound. The
// protocol checks the TypeScript package gets from oauth4webapi (discovery, authorization response, token response
// and ID token validation, JWKS key selection) are implemented here.

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// FederatedIdentity is what the host's CompleteAuthentication receives (a record with the TypeScript members:
// tenantId, providerId, issuer, subject, email, emailVerified, name, attributes, trustScimProvisioned,
// linkingIdentityId, linkingSessionId).
type FederatedIdentity = *core.Object

// MappedProfile is a generic OAuth2 profile mapper's result.
type MappedProfile struct {
	Subject       string
	Email         *string
	EmailVerified *bool
	Name          *string
}

// OAuthLoginConnection is one upstream identity provider.
type OAuthLoginConnection struct {
	ID       string
	TenantID string
	// Kind is oidc, oauth2, google, github or microsoft.
	Kind         string
	ClientID     string
	ClientSecret string
	// RedirectURI is the fixed, registered callback URL. Never supplied by the browser.
	RedirectURI string
	Issuer      string
	// Scopes nil means the kind's defaults.
	Scopes                []string
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserInfoEndpoint      string
	// MicrosoftTenant is the Entra directory: organizations (default), common, consumers, or a tenant ID or domain.
	MicrosoftTenant string
	// AllowedMicrosoftTenants are the Entra tenant IDs a multi-tenant Microsoft connection accepts.
	AllowedMicrosoftTenants []string
	// AllowedEmailDomains are the email domains whose verified addresses may enroll (nil: unset).
	AllowedEmailDomains []string
	// TrustScimProvisioned is nil, a bool, or a list of SCIM connection IDs.
	TrustScimProvisioned any
	// MapProfile maps a generic OAuth2 profile; required for oauth2.
	MapProfile func(profile *core.Object) (*MappedProfile, error)
	// MapAttributes maps verified claims or the profile to identity attributes (nil result: untouched).
	MapAttributes func(claims *core.Object) (*core.Object, error)
}

// OAuthLoginConfig configures createOAuthLogin.
type OAuthLoginConfig struct {
	Store       core.IamStore
	Connections []OAuthLoginConnection
	// CompleteAuthentication receives only protocol-verified claims; it must apply local MFA.
	CompleteAuthentication func(ctx context.Context, identity FederatedIdentity) (any, error)
	Authenticate           func(ctx context.Context, credential core.CredentialInput) (*auth.Principal, error)
	TrustedOrigins         []string
	BasePath               string
	// AllowInsecureLocalhost is for tests and local development; production requires HTTPS everywhere.
	AllowInsecureLocalhost bool
	// HTTPClient sends the provider requests (default: no redirects followed).
	HTTPClient *http.Client
	// Now overrides the clock (epoch milliseconds).
	Now func() int64
}

// LoginHints are optional hints forwarded to the identity provider's sign-in page.
type LoginHints struct {
	LoginHint  *string
	DomainHint *string
	// Prompt is login, select_account, consent or none.
	Prompt *string
}

// BeginResult is begin's result.
type BeginResult struct {
	URL       string `json:"url"`
	Binding   string `json:"binding"`
	State     string `json:"state"`
	ExpiresAt int64  `json:"expiresAt"`
}

var multiTenantDirectories = []string{"common", "organizations", "consumers"}

const microsoftAuthority = "https://login.microsoftonline.com"

// OAuthLoginService is createOAuthLogin's result.
type OAuthLoginService struct {
	config      OAuthLoginConfig
	BasePath    string
	connections map[string]*OAuthLoginConnection
	order       []string
	client      *http.Client
	now         func() int64
}

func (s *OAuthLoginService) url(value string) (*parsedURL, error) {
	return endpointURL(value, s.config.AllowInsecureLocalhost)
}

func endpointURL(value string, allowLocalhost bool) (*parsedURL, error) {
	parsed, err := parseURL(value)
	if err != nil {
		return nil, &core.TypeError{Message: "Invalid URL"}
	}
	if urlHasCredentials(parsed) || urlHasHash(parsed) ||
		(parsed.Protocol != "https:" && !(allowLocalhost && parsed.Protocol == "http:" && contains(loopbacks, parsed.Hostname))) {
		return nil, core.NewIamError("configuration", "OAuth endpoints require HTTPS (or explicitly enabled localhost HTTP).")
	}
	return parsed, nil
}

func activeTenant(ctx context.Context, store core.IamStore, id string) error {
	active, err := core.TenantTreeActive(ctx, store, id)
	if err != nil {
		return err
	}
	if !active {
		return core.NewIamError("TENANT_INACTIVE", "Tenant is unavailable.", 403)
	}
	return nil
}

var (
	emailDomainPattern  = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$`)
	microsoftTenantName = regexp.MustCompile(`^[A-Za-z0-9.-]{1,128}$`)
	uuidPattern         = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	domainHintPattern   = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
)

// CreateOAuthLogin is createOAuthLogin.
func CreateOAuthLogin(config OAuthLoginConfig) (*OAuthLoginService, error) {
	basePath := config.BasePath
	if basePath == "" {
		basePath = "/oauth/login"
	}
	basePath = strings.TrimSuffix(basePath, "/")
	s := &OAuthLoginService{config: config, BasePath: basePath, connections: map[string]*OAuthLoginConnection{}, now: config.Now}
	if s.now == nil {
		s.now = wallNow
	}
	s.client = config.HTTPClient
	if s.client == nil {
		s.client = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	for index := range config.Connections {
		connection := config.Connections[index]
		if connection.ID == "" || s.connections[connection.ID] != nil || connection.TenantID == "" || connection.ClientID == "" {
			return nil, core.NewIamError("configuration", "OAuth connection IDs must be unique and configuration complete.")
		}
		if _, err := s.url(connection.RedirectURI); err != nil {
			return nil, err
		}
		if (connection.Kind == "oidc" || connection.Kind == "oauth2") && connection.Issuer == "" {
			return nil, core.NewIamError("configuration", "The provider issuer is required.")
		}
		if connection.AllowedEmailDomains != nil {
			invalid := len(connection.AllowedEmailDomains) == 0
			for _, domain := range connection.AllowedEmailDomains {
				if !emailDomainPattern.MatchString(domain) {
					invalid = true
				}
			}
			if invalid {
				return nil, core.NewIamError("configuration", "allowedEmailDomains must list one or more exact domain names.")
			}
		}
		if connection.Issuer != "" {
			if _, err := s.url(connection.Issuer); err != nil {
				return nil, err
			}
		}
		if trust := connection.TrustScimProvisioned; trust != nil {
			valid := false
			switch value := trust.(type) {
			case bool:
				valid = true
			case []string:
				valid = len(value) <= 20
				for _, id := range value {
					if id == "" || core.UTF16Len(id) > 128 {
						valid = false
					}
				}
			case []any:
				valid = len(value) <= 20
				for _, item := range value {
					id, ok := item.(string)
					if !ok || id == "" || core.UTF16Len(id) > 128 {
						valid = false
					}
				}
			}
			if !valid {
				return nil, core.NewIamError("configuration", "trustScimProvisioned is a boolean or a list of SCIM connection IDs.")
			}
		}
		if connection.Kind == "microsoft" {
			directory := connection.MicrosoftTenant
			if directory == "" {
				directory = "organizations"
			}
			if !microsoftTenantName.MatchString(directory) {
				return nil, core.NewIamError("configuration", "microsoftTenant must be a tenant ID, domain, or alias.")
			}
			if contains(multiTenantDirectories, strings.ToLower(directory)) && len(connection.AllowedMicrosoftTenants) == 0 {
				return nil, core.NewIamError("configuration", "Multi-tenant Microsoft connections need allowedMicrosoftTenants.")
			}
		}
		if connection.Kind == "github" && connection.ClientSecret == "" {
			return nil, core.NewIamError("configuration", "GitHub client secret is required.")
		}
		for _, existing := range s.order {
			if s.connections[existing].RedirectURI == connection.RedirectURI {
				return nil, core.NewIamError("configuration", "OAuth callback URLs must be unique per connection.")
			}
		}
		if connection.Kind == "oauth2" {
			if connection.AuthorizationEndpoint == "" || connection.TokenEndpoint == "" || connection.UserInfoEndpoint == "" || connection.MapProfile == nil {
				return nil, core.NewIamError("configuration", "Generic OAuth2 requires authorization/token/profile endpoints and a trusted profile mapper.")
			}
			for _, endpoint := range []string{connection.AuthorizationEndpoint, connection.TokenEndpoint, connection.UserInfoEndpoint} {
				if _, err := s.url(endpoint); err != nil {
					return nil, err
				}
			}
		}
		copy := connection
		s.connections[connection.ID] = &copy
		s.order = append(s.order, connection.ID)
	}
	return s, nil
}

func (s *OAuthLoginService) connection(id string) (*OAuthLoginConnection, error) {
	found := s.connections[id]
	if found == nil {
		return nil, core.NewIamError("NOT_FOUND", "OAuth connection not found.", 404)
	}
	return found, nil
}

// oauthError is an oauth4webapi OperationProcessingError (or one of its siblings).
type oauthError struct {
	Code    string
	Message string
}

func (e *oauthError) Error() string { return e.Message }

func ope(message, code string) *oauthError { return &oauthError{Code: code, Message: message} }

// authorizationServer is oauth4webapi's AuthorizationServer metadata.
type authorizationServer = *core.Object

func (s *OAuthLoginService) fetch(ctx context.Context, method, target string, header http.Header, body string, timeout time.Duration) (*http.Response, []byte, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, nil, err
	}
	for key, values := range header {
		for _, value := range values {
			request.Header.Add(key, value)
		}
	}
	response, err := s.client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, nil, err
	}
	return response, raw, nil
}

func (s *OAuthLoginService) checkProtocol(u string) error {
	parsed, err := parseURL(u)
	if err != nil {
		return ope("Invalid URL", "ERR_INVALID_ARG_VALUE")
	}
	if !s.config.AllowInsecureLocalhost && parsed.Protocol != "https:" {
		return ope("only requests to HTTPS are allowed", "OAUTH_HTTP_REQUEST_FORBIDDEN")
	}
	if parsed.Protocol != "https:" && parsed.Protocol != "http:" {
		return ope("only HTTP and HTTPS requests are allowed", "OAUTH_REQUEST_PROTOCOL_FORBIDDEN")
	}
	return nil
}

// jsonBody is getResponseJsonBody: a top-level JSON object.
func jsonBody(raw []byte) (*core.Object, error) {
	parsed, err := core.ParseJSON(raw)
	if err != nil {
		return nil, ope(`failed to parse "response" body as JSON`, "OAUTH_PARSE_ERROR")
	}
	body, ok := parsed.(*core.Object)
	if !ok || body == nil {
		return nil, ope(`"response" body must be a top level object`, "OAUTH_INVALID_RESPONSE")
	}
	return body, nil
}

// microsoftMetadata is Entra ID discovery: every endpoint must live on the configured authority.
func (s *OAuthLoginService) microsoftMetadata(ctx context.Context, item *OAuthLoginConnection) (authorizationServer, error) {
	issuer := item.Issuer
	if issuer == "" {
		issuer = microsoftAuthority
	}
	authority, err := s.url(issuer)
	if err != nil {
		return nil, err
	}
	root := urlOrigin(authority) + strings.TrimSuffix(urlPathname(authority), "/")
	directory := item.MicrosoftTenant
	if directory == "" {
		directory = "organizations"
	}
	discoveryFailed := core.NewIamError("OAUTH_DISCOVERY", "Microsoft discovery failed.", 502)
	header := http.Header{}
	header.Set("accept", "application/json")
	response, raw, err := s.fetch(ctx, http.MethodGet, root+"/"+encodeURIComponent(directory)+"/v2.0/.well-known/openid-configuration", header, "", 10*time.Second)
	if err != nil || response.StatusCode < 200 || response.StatusCode > 299 || (response.StatusCode >= 300 && response.StatusCode < 400) {
		return nil, discoveryFailed
	}
	parsed, err := core.ParseJSON(raw)
	if err != nil {
		return nil, discoveryFailed
	}
	document, ok := parsed.(*core.Object)
	if !ok || document == nil {
		if parsed == nil {
			return nil, discoveryFailed
		}
		document = core.NewObject()
	}
	documentIssuer, _ := document.Get("issuer").(string)
	if !strings.HasPrefix(documentIssuer, root+"/") || !strings.HasSuffix(documentIssuer, "/v2.0") {
		return nil, core.NewIamError("OAUTH_DISCOVERY", "Unexpected Microsoft issuer.", 502)
	}
	for _, key := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri"} {
		endpoint := document.Get(key)
		if !truthy(endpoint) {
			return nil, core.NewIamError("OAUTH_DISCOVERY", "Microsoft metadata is incomplete.", 502)
		}
		parsedEndpoint, err := s.url(jsString(endpoint))
		if err != nil {
			return nil, err
		}
		if urlOrigin(parsedEndpoint) != urlOrigin(authority) {
			return nil, core.NewIamError("OAUTH_DISCOVERY", "Microsoft endpoints must use the authority.", 502)
		}
	}
	return document, nil
}

// microsoftIssuer is the concrete issuer of the directory that signed in, after checking allowedMicrosoftTenants.
func (s *OAuthLoginService) microsoftIssuer(item *OAuthLoginConnection, discovered authorizationServer, tokenBody []byte) (authorizationServer, error) {
	tid := ""
	if parsed, err := core.ParseJSON(tokenBody); err == nil {
		if body, ok := parsed.(*core.Object); ok && body != nil {
			parts := strings.Split(jsString(body.Get("id_token")), ".")
			if len(parts) > 1 {
				if payload, err := core.ParseJSON(nodeBase64Decode(parts[1])); err == nil {
					if claims, ok := payload.(*core.Object); ok && claims != nil {
						tid, _ = claims.Get("tid").(string)
					}
				}
			}
		}
	}
	if !uuidPattern.MatchString(tid) {
		return nil, core.NewIamError("OAUTH_PROFILE", "The Microsoft ID token names no directory.", 401)
	}
	if len(item.AllowedMicrosoftTenants) > 0 {
		allowed := false
		for _, candidate := range item.AllowedMicrosoftTenants {
			if strings.EqualFold(candidate, tid) {
				allowed = true
			}
		}
		if !allowed {
			return nil, core.NewIamError("OAUTH_TENANT", "This Microsoft directory may not sign in here.", 403)
		}
	}
	// A single-tenant document already names its issuer; the ID token check compares against it.
	issuer := str(discovered, "issuer")
	if strings.Contains(issuer, "{tenantid}") {
		return discovered.Spread(core.NewObject("issuer", strings.Replace(issuer, "{tenantid}", tid, 1))), nil
	}
	return discovered, nil
}

func (s *OAuthLoginService) metadata(ctx context.Context, item *OAuthLoginConnection) (authorizationServer, error) {
	switch item.Kind {
	case "github":
		return core.NewObject("issuer", "https://github.com", "authorization_endpoint", "https://github.com/login/oauth/authorize",
			"token_endpoint", "https://github.com/login/oauth/access_token"), nil
	case "oauth2":
		return core.NewObject("issuer", item.Issuer, "authorization_endpoint", item.AuthorizationEndpoint,
			"token_endpoint", item.TokenEndpoint, "userinfo_endpoint", item.UserInfoEndpoint), nil
	case "microsoft":
		return s.microsoftMetadata(ctx, item)
	}
	issuerValue := item.Issuer
	if item.Kind == "google" {
		issuerValue = "https://accounts.google.com"
	}
	issuer, err := s.url(issuerValue)
	if err != nil {
		return nil, err
	}
	if err := s.checkProtocol(issuer.Href); err != nil {
		return nil, err
	}
	discovery := *issuer.URL
	discovery.Path = strings.ReplaceAll(discovery.Path+"/.well-known/openid-configuration", "//", "/")
	discovery.RawPath = ""
	header := http.Header{}
	header.Set("accept", "application/json")
	response, raw, err := s.fetch(ctx, http.MethodGet, discovery.String(), header, "", 0)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != 200 {
		return nil, ope(`"response" is not a conform Authorization Server Metadata response (unexpected HTTP status code)`, "OAUTH_RESPONSE_IS_NOT_CONFORM")
	}
	result, err := jsonBody(raw)
	if err != nil {
		return nil, err
	}
	documentIssuer, ok := result.Get("issuer").(string)
	if !ok {
		return nil, ope(`"response" body "issuer" property must be a string`, "OAUTH_INVALID_RESPONSE")
	}
	parsedIssuer, err := parseURL(documentIssuer)
	if err != nil || parsedIssuer.Href != issuer.Href {
		return nil, ope(`"response" body "issuer" property does not match the expected value`, "OAUTH_JSON_ATTRIBUTE_COMPARISON_FAILED")
	}
	for _, key := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint"} {
		if endpoint := result.Get(key); truthy(endpoint) {
			if _, err := s.url(jsString(endpoint)); err != nil {
				return nil, err
			}
		}
	}
	return result, nil
}

// hints validates sign-in hints: never trusted for identity, only forwarded to the provider's login screen.
func hints(input *LoginHints) (*LoginHints, error) {
	result := &LoginHints{}
	if input == nil {
		return result, nil
	}
	if input.LoginHint != nil {
		value := *input.LoginHint
		if value == "" || core.UTF16Len(value) > 320 || strings.ContainsAny(value, "<>") || hasJSSpace(value) {
			return nil, core.NewIamError("INVALID_INPUT", "login_hint must be a short identifier such as an email address.", 400)
		}
		result.LoginHint = input.LoginHint
	}
	if input.DomainHint != nil {
		if !domainHintPattern.MatchString(*input.DomainHint) {
			return nil, core.NewIamError("INVALID_INPUT", "domain_hint must be a domain name.", 400)
		}
		result.DomainHint = input.DomainHint
	}
	if input.Prompt != nil {
		if !contains([]string{"login", "select_account", "consent", "none"}, *input.Prompt) {
			return nil, core.NewIamError("INVALID_INPUT", "prompt must be login, select_account, consent, or none.", 400)
		}
		result.Prompt = input.Prompt
	}
	return result, nil
}

// hasJSSpace is /\s/ in JavaScript.
func hasJSSpace(s string) bool {
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\v', '\f', '\r', 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
			return true
		}
		if r >= 0x2000 && r <= 0x200A {
			return true
		}
	}
	return false
}

// searchParams is URLSearchParams over a URL's query, with set semantics.
type searchParams struct{ pairs [][2]string }

func newSearchParams(rawQuery string) *searchParams {
	params := &searchParams{}
	if rawQuery == "" {
		return params
	}
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		key, value := part, ""
		if index := strings.Index(part, "="); index >= 0 {
			key, value = part[:index], part[index+1:]
		}
		params.pairs = append(params.pairs, [2]string{queryUnescape(strings.ReplaceAll(key, "+", " ")), queryUnescape(strings.ReplaceAll(value, "+", " "))})
	}
	return params
}

// set replaces the first pair named key and drops the others, or appends one.
func (p *searchParams) set(key, value string) {
	out := p.pairs[:0:0]
	found := false
	for _, pair := range p.pairs {
		if pair[0] == key {
			if !found {
				out = append(out, [2]string{key, value})
				found = true
			}
			continue
		}
		out = append(out, pair)
	}
	if !found {
		out = append(out, [2]string{key, value})
	}
	p.pairs = out
}

func (p *searchParams) get(key string) (string, bool) {
	for _, pair := range p.pairs {
		if pair[0] == key {
			return pair[1], true
		}
	}
	return "", false
}

func (p *searchParams) String() string { return formEncode(p.pairs) }

func defaultScopes(item *OAuthLoginConnection) []string {
	if item.Scopes != nil {
		return item.Scopes
	}
	switch item.Kind {
	case "github":
		return []string{"read:user", "user:email"}
	case "oauth2":
		return []string{}
	}
	return []string{"openid", "email", "profile"}
}

// Begin starts a sign-in (or, with a linking credential, an account link) for a connection.
func (s *OAuthLoginService) Begin(ctx context.Context, connectionID string, linkingCredential *core.CredentialInput, loginHints *LoginHints) (*BeginResult, error) {
	requested, err := hints(loginHints)
	if err != nil {
		return nil, err
	}
	item, err := s.connection(connectionID)
	if err != nil {
		return nil, err
	}
	if err := activeTenant(ctx, s.config.Store, item.TenantID); err != nil {
		return nil, err
	}
	linkingSessionID, linkingIdentityID := "", ""
	if linkingCredential != nil {
		if s.config.Authenticate == nil {
			return nil, core.NewIamError("configuration", "Linking requires an authenticate callback.")
		}
		principal, err := s.config.Authenticate(ctx, *linkingCredential)
		if err != nil {
			return nil, err
		}
		authenticatedAt, _ := num(principal.Session, "authenticatedAt")
		age := float64(s.now()) - authenticatedAt
		if str(principal.Identity, "tenantId") != item.TenantID || truthy(principal.Identity.Get("rootAdmin")) ||
			str(principal.Session, "kind") != "user" || age < 0 || age > 300_000 {
			return nil, core.NewIamError("RECENT_AUTH_REQUIRED", "Linking requires recent authentication to a non-root identity in this tenant.", 403)
		}
		linkingSessionID, linkingIdentityID = str(principal.Session, "id"), str(principal.Identity, "id")
	}
	as, err := s.metadata(ctx, item)
	if err != nil {
		return nil, err
	}
	endpoint := as.Get("authorization_endpoint")
	if !truthy(endpoint) {
		return nil, core.NewIamError("configuration", "Authorization endpoint is missing.")
	}
	state, codeVerifier, nonce, binding := randomB64URL(32), randomB64URL(32), randomB64URL(32), randomB64URL(32)
	authorizationURL, err := parseURL(jsString(endpoint))
	if err != nil {
		return nil, &core.TypeError{Message: "Invalid URL"}
	}
	params := newSearchParams(authorizationURL.RawQuery)
	params.set("client_id", item.ClientID)
	params.set("redirect_uri", item.RedirectURI)
	params.set("response_type", "code")
	if scopes := defaultScopes(item); len(scopes) > 0 {
		params.set("scope", strings.Join(scopes, " "))
	}
	if requested.LoginHint != nil && item.Kind != "github" {
		params.set("login_hint", *requested.LoginHint)
	}
	if requested.LoginHint != nil && item.Kind == "github" {
		params.set("login", *requested.LoginHint)
	}
	if requested.DomainHint != nil && item.Kind == "microsoft" {
		params.set("domain_hint", *requested.DomainHint)
	}
	if requested.DomainHint != nil && item.Kind == "google" {
		params.set("hd", *requested.DomainHint)
	}
	if requested.Prompt != nil && item.Kind != "github" {
		params.set("prompt", *requested.Prompt)
	}
	params.set("state", state)
	params.set("code_challenge", sha256B64URL(codeVerifier))
	params.set("code_challenge_method", "S256")
	if item.Kind == "oidc" || item.Kind == "google" || item.Kind == "microsoft" {
		params.set("nonce", nonce)
	}
	target := *authorizationURL.URL
	target.RawQuery = params.String()
	err = s.config.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		if err := activeTenant(ctx, tx, item.TenantID); err != nil {
			return err
		}
		record := core.NewObject("id", hash(state), "tenantId", item.TenantID, "connectionId", connectionID, "state", state,
			"codeVerifier", codeVerifier, "nonce", nonce, "bindingHash", hash(binding), "expiresAt", s.now()+600_000)
		if linkingIdentityID != "" {
			record.Set("linkingIdentityId", linkingIdentityID)
		}
		if linkingSessionID != "" {
			record.Set("linkingSessionId", linkingSessionID)
		}
		_, err := tx.Insert(ctx, "oauthLoginStates", record)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &BeginResult{URL: target.String(), Binding: binding, State: state, ExpiresAt: s.now() + 600_000}, nil
}

// tokenRequest is authorizationCodeGrantRequest.
func (s *OAuthLoginService) tokenRequest(ctx context.Context, as authorizationServer, item *OAuthLoginConnection, code, codeVerifier string) (*http.Response, []byte, error) {
	endpoint, ok := as.Get("token_endpoint").(string)
	if !ok {
		return nil, nil, ope(`authorization server metadata does not contain a valid "as.token_endpoint"`, "OAUTH_MISSING_SERVER_METADATA")
	}
	if err := s.checkProtocol(endpoint); err != nil {
		return nil, nil, err
	}
	body := [][2]string{{"redirect_uri", item.RedirectURI}, {"code", code}, {"code_verifier", codeVerifier}, {"grant_type", "authorization_code"}, {"client_id", item.ClientID}}
	if item.ClientSecret != "" {
		body = append(body, [2]string{"client_secret", item.ClientSecret})
	}
	header := http.Header{}
	header.Set("accept", "application/json")
	header.Set("content-type", "application/x-www-form-urlencoded;charset=UTF-8")
	return s.fetch(ctx, http.MethodPost, endpoint, header, formEncode(body), 0)
}

// checkChallenges is checkAuthenticationChallenges: a response carrying a WWW-Authenticate challenge fails.
func checkChallenges(response *http.Response) error {
	if value := strings.TrimSpace(response.Header.Get("www-authenticate")); value != "" {
		return &oauthError{Code: "OAUTH_WWW_AUTHENTICATE_CHALLENGE", Message: "server responded with a challenge in the WWW-Authenticate HTTP Header"}
	}
	return nil
}

// processTokenResponse is processAuthorizationCodeResponse (OpenID when expectedNonce is set).
func (s *OAuthLoginService) processTokenResponse(as authorizationServer, item *OAuthLoginConnection, response *http.Response, raw []byte, openID bool, expectedNonce string) (*core.Object, *core.Object, string, error) {
	if response.StatusCode != 200 {
		if err := checkChallenges(response); err != nil {
			return nil, nil, "", err
		}
		if parsed, err := core.ParseJSON(raw); err == nil {
			if body, ok := parsed.(*core.Object); ok && body != nil {
				if _, ok := body.Get("error").(string); ok {
					return nil, nil, "", &oauthError{Code: "OAUTH_RESPONSE_BODY_ERROR", Message: "server responded with an error in the response body"}
				}
			}
		}
		return nil, nil, "", ope(`"response" is not a conform Token Endpoint response (unexpected HTTP status code)`, "OAUTH_RESPONSE_IS_NOT_CONFORM")
	}
	result, err := jsonBody(raw)
	if err != nil {
		return nil, nil, "", err
	}
	if _, ok := result.Get("access_token").(string); !ok {
		return nil, nil, "", ope(`"response" body "access_token" property must be a string`, "OAUTH_INVALID_RESPONSE")
	}
	tokenType, ok := result.Get("token_type").(string)
	if !ok {
		return nil, nil, "", ope(`"response" body "token_type" property must be a string`, "OAUTH_INVALID_RESPONSE")
	}
	tokenType = strings.ToLower(tokenType)
	if value := result.Get("refresh_token"); !isUndefined(value) {
		if _, ok := value.(string); !ok {
			return nil, nil, "", ope(`"response" body "refresh_token" property must be a string`, "OAUTH_INVALID_RESPONSE")
		}
	}
	if value := result.Get("scope"); !isUndefined(value) {
		if _, ok := value.(string); !ok {
			return nil, nil, "", ope(`"response" body "scope" property must be a string`, "OAUTH_INVALID_RESPONSE")
		}
	}
	var claims *core.Object
	idToken := ""
	if value := result.Get("id_token"); !isUndefined(value) {
		text, ok := value.(string)
		if !ok {
			return nil, nil, "", ope(`"response" body "id_token" property must be a string`, "OAUTH_INVALID_RESPONSE")
		}
		required := []string{}
		if openID && expectedNonce != "" {
			required = append(required, "nonce")
		}
		claims, err = s.validateIDTokenClaims(as, item, text, required)
		if err != nil {
			return nil, nil, "", err
		}
		idToken = text
	}
	if tokenType != "dpop" && tokenType != "bearer" {
		return nil, nil, "", &oauthError{Code: "OAUTH_UNSUPPORTED_OPERATION", Message: "unsupported `token_type` value"}
	}
	if openID {
		if idToken == "" {
			return nil, nil, "", ope(`"response" body "id_token" property must be a string`, "OAUTH_INVALID_RESPONSE")
		}
		if !jsEq(claims.Get("nonce"), expectedNonce) {
			return nil, nil, "", ope(`unexpected ID Token "nonce" claim value`, "OAUTH_JWT_CLAIM_COMPARISON_FAILED")
		}
	} else if claims != nil && !isUndefined(claims.Get("nonce")) {
		return nil, nil, "", ope(`unexpected ID Token "nonce" claim value`, "OAUTH_JWT_CLAIM_COMPARISON_FAILED")
	}
	return result, claims, idToken, nil
}

// validateIDTokenClaims is validateIdTokenClaims + the authorized party and auth_time checks.
func (s *OAuthLoginService) validateIDTokenClaims(as authorizationServer, item *OAuthLoginConnection, idToken string, required []string) (*core.Object, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) == 5 {
		return nil, &oauthError{Code: "OAUTH_UNSUPPORTED_OPERATION", Message: "JWE decryption is not configured"}
	}
	if len(parts) != 3 {
		return nil, ope("Invalid JWT", "OAUTH_INVALID_RESPONSE")
	}
	headerValue, err := core.ParseJSON(nodeBase64Decode(parts[0]))
	header, ok := headerValue.(*core.Object)
	if err != nil {
		return nil, ope("failed to parse JWT Header body as base64url encoded JSON", "OAUTH_PARSE_ERROR")
	}
	if !ok || header == nil {
		return nil, ope("JWT Header must be a top level object", "OAUTH_INVALID_RESPONSE")
	}
	alg := jsString(header.Get("alg"))
	if supported, ok := as.Get("id_token_signing_alg_values_supported").([]any); ok {
		if !contains(stringList(supported), alg) || isUndefined(header.Get("alg")) {
			return nil, ope(`unexpected JWT "alg" header parameter`, "OAUTH_INVALID_RESPONSE")
		}
	} else if alg != "RS256" {
		return nil, ope(`unexpected JWT "alg" header parameter`, "OAUTH_INVALID_RESPONSE")
	}
	if !isUndefined(header.Get("crit")) {
		return nil, &oauthError{Code: "OAUTH_UNSUPPORTED_OPERATION", Message: `no JWT "crit" header parameter extensions are supported`}
	}
	claimsValue, err := core.ParseJSON(nodeBase64Decode(parts[1]))
	claims, ok := claimsValue.(*core.Object)
	if err != nil {
		return nil, ope("failed to parse JWT Payload body as base64url encoded JSON", "OAUTH_PARSE_ERROR")
	}
	if !ok || claims == nil {
		return nil, ope("JWT Payload must be a top level object", "OAUTH_INVALID_RESPONSE")
	}
	now := float64(epoch(s.now()))
	const tolerance = 30
	if value := claims.Get("exp"); !isUndefined(value) {
		exp, ok := value.(float64)
		if !ok {
			return nil, ope(`unexpected JWT "exp" (expiration time) claim type`, "OAUTH_INVALID_RESPONSE")
		}
		if exp <= now-tolerance {
			return nil, ope(`unexpected JWT "exp" (expiration time) claim value, expiration is past current timestamp`, "OAUTH_JWT_TIMESTAMP_CHECK_FAILED")
		}
	}
	if value := claims.Get("iat"); !isUndefined(value) {
		if _, ok := value.(float64); !ok {
			return nil, ope(`unexpected JWT "iat" (issued at) claim type`, "OAUTH_INVALID_RESPONSE")
		}
	}
	if value := claims.Get("iss"); !isUndefined(value) {
		if _, ok := value.(string); !ok {
			return nil, ope(`unexpected JWT "iss" (issuer) claim type`, "OAUTH_INVALID_RESPONSE")
		}
	}
	if value := claims.Get("nbf"); !isUndefined(value) {
		nbf, ok := value.(float64)
		if !ok {
			return nil, ope(`unexpected JWT "nbf" (not before) claim type`, "OAUTH_INVALID_RESPONSE")
		}
		if nbf > now+tolerance {
			return nil, ope(`unexpected JWT "nbf" (not before) claim value`, "OAUTH_JWT_TIMESTAMP_CHECK_FAILED")
		}
	}
	if value := claims.Get("aud"); !isUndefined(value) {
		switch aud := value.(type) {
		case string:
		case []any:
			for _, item := range aud {
				if _, ok := item.(string); !ok {
					return nil, ope(`unexpected JWT "aud" (audience) claim type`, "OAUTH_INVALID_RESPONSE")
				}
			}
		default:
			return nil, ope(`unexpected JWT "aud" (audience) claim type`, "OAUTH_INVALID_RESPONSE")
		}
	}
	for _, claim := range append([]string{"aud", "exp", "iat", "iss", "sub"}, required...) {
		if isUndefined(claims.Get(claim)) {
			return nil, ope(`JWT "`+claim+`" claim missing`, "OAUTH_INVALID_RESPONSE")
		}
	}
	if !jsEq(claims.Get("iss"), as.Get("issuer")) {
		return nil, ope(`unexpected JWT "iss" (issuer) claim value`, "OAUTH_JWT_CLAIM_COMPARISON_FAILED")
	}
	switch aud := claims.Get("aud").(type) {
	case []any:
		if !contains(stringList(aud), item.ClientID) {
			return nil, ope(`unexpected JWT "aud" (audience) claim value`, "OAUTH_JWT_CLAIM_COMPARISON_FAILED")
		}
		if len(aud) != 1 {
			if isUndefined(claims.Get("azp")) {
				return nil, ope(`ID Token "aud" (audience) claim includes additional untrusted audiences`, "OAUTH_JWT_CLAIM_COMPARISON_FAILED")
			}
			if !jsEq(claims.Get("azp"), item.ClientID) {
				return nil, ope(`unexpected ID Token "azp" (authorized party) claim value`, "OAUTH_JWT_CLAIM_COMPARISON_FAILED")
			}
		}
	default:
		if !jsEq(aud, item.ClientID) {
			return nil, ope(`unexpected JWT "aud" (audience) claim value`, "OAUTH_JWT_CLAIM_COMPARISON_FAILED")
		}
	}
	if _, ok := claims.Get("sub").(string); !ok {
		return nil, ope(`unexpected JWT "sub" (subject) claim type`, "OAUTH_INVALID_RESPONSE")
	}
	if value := claims.Get("auth_time"); !isUndefined(value) {
		if number, ok := value.(float64); !ok || number < 0 {
			return nil, ope(`ID Token "auth_time" (authentication time) must be a non-negative number`, "OAUTH_INVALID_RESPONSE")
		}
	}
	return claims, nil
}

// validateSignature is validateApplicationLevelSignature: the ID token's signature against the issuer's JWKS.
func (s *OAuthLoginService) validateSignature(ctx context.Context, as authorizationServer, idToken string) error {
	parts := strings.Split(idToken, ".")
	headerValue, _ := core.ParseJSON(nodeBase64Decode(parts[0]))
	header, _ := headerValue.(*core.Object)
	alg := str(header, "alg")
	if strings.HasPrefix(alg, "HS") {
		return &oauthError{Code: "OAUTH_UNSUPPORTED_OPERATION", Message: "unsupported JWS algorithm"}
	}
	entry, ok := joseAlgorithms[alg]
	if !ok || entry.kty == "AKP" {
		return &oauthError{Code: "OAUTH_UNSUPPORTED_OPERATION", Message: "unsupported JWS algorithm"}
	}
	jwksURI, ok := as.Get("jwks_uri").(string)
	if !ok {
		return ope(`authorization server metadata does not contain a valid "as.jwks_uri"`, "OAUTH_MISSING_SERVER_METADATA")
	}
	if err := s.checkProtocol(jwksURI); err != nil {
		return err
	}
	headers := http.Header{}
	headers.Set("accept", "application/json")
	headers.Add("accept", "application/jwk-set+json")
	response, raw, err := s.fetch(ctx, http.MethodGet, jwksURI, headers, "", 0)
	if err != nil {
		return err
	}
	if response.StatusCode != 200 {
		return ope(`"response" is not a conform JSON Web Key Set response (unexpected HTTP status code)`, "OAUTH_RESPONSE_IS_NOT_CONFORM")
	}
	jwks, err := jsonBody(raw)
	if err != nil {
		return err
	}
	keys, ok := jwks.Get("keys").([]any)
	if !ok {
		return ope(`"response" body must include a "keys" array`, "OAUTH_INVALID_RESPONSE")
	}
	kid := header.Get("kid")
	var candidates []*core.Object
	for _, value := range keys {
		jwk, ok := value.(*core.Object)
		if !ok || jwk == nil || str(jwk, "kty") != entry.kty {
			continue
		}
		if !isUndefined(kid) && !jsEq(kid, jwk.Get("kid")) {
			continue
		}
		if !isUndefined(jwk.Get("alg")) && !jsEq(jwk.Get("alg"), alg) {
			continue
		}
		if !isUndefined(jwk.Get("use")) && !jsEq(jwk.Get("use"), "sig") {
			continue
		}
		if ops, ok := jwk.Get("key_ops").([]any); ok && !contains(stringList(ops), "verify") {
			continue
		}
		if entry.crv != "" && str(jwk, "crv") != entry.crv {
			continue
		}
		candidates = append(candidates, jwk)
	}
	if len(candidates) == 0 {
		return ope("error when selecting a JWT verification key, no applicable keys found", "OAUTH_KEY_SELECTION_FAILED")
	}
	if len(candidates) != 1 {
		return ope(`error when selecting a JWT verification key, multiple applicable keys found, a "kid" JWT Header Parameter is required`, "OAUTH_KEY_SELECTION_FAILED")
	}
	key, err := joseImportPublic(publicJWK(candidates[0]), alg)
	if err != nil {
		return err
	}
	if entry.minRsaBits > 0 && key.rsaBits < entry.minRsaBits {
		return ope(`"key" uses an unsupported RSA modulus length`, "OAUTH_INVALID_RESPONSE")
	}
	signature, err := joseDecode(parts[2])
	if err != nil || !joseVerifySignature(entry, key, signature, []byte(parts[0]+"."+parts[1])) {
		return ope("JWT signature verification failed", "OAUTH_INVALID_RESPONSE")
	}
	return nil
}

// resourceRequest is protectedResourceRequest: a bearer GET that fails on a WWW-Authenticate challenge.
func (s *OAuthLoginService) resourceRequest(ctx context.Context, accessToken, target string, accept string, extra map[string]string) (*http.Response, []byte, error) {
	if err := s.checkProtocol(target); err != nil {
		return nil, nil, err
	}
	header := http.Header{}
	header.Set("accept", accept)
	for key, value := range extra {
		header.Set(key, value)
	}
	header.Set("authorization", "Bearer "+accessToken)
	response, raw, err := s.fetch(ctx, http.MethodGet, target, header, "", 0)
	if err != nil {
		return nil, nil, err
	}
	if err := checkChallenges(response); err != nil {
		return nil, nil, err
	}
	return response, raw, nil
}

func okStatus(response *http.Response) bool {
	return response.StatusCode >= 200 && response.StatusCode <= 299
}

// Callback completes a sign-in from the provider's redirect (callbackURL) and the browser binding cookie.
func (s *OAuthLoginService) Callback(ctx context.Context, connectionID, callbackURL, binding string) (any, error) {
	item, err := s.connection(connectionID)
	if err != nil {
		return nil, err
	}
	returned, err := parseURL(callbackURL)
	if err != nil {
		return nil, &core.TypeError{Message: "Invalid URL"}
	}
	expected, err := parseURL(item.RedirectURI)
	if err != nil {
		return nil, &core.TypeError{Message: "Invalid URL"}
	}
	if urlOrigin(returned) != urlOrigin(expected) || urlPathname(returned) != urlPathname(expected) {
		return nil, core.NewIamError("OAUTH_CALLBACK", "Unexpected callback URL.", 400)
	}
	returnedParams := newSearchParams(returned.RawQuery)
	stateValue, _ := returnedParams.get("state")
	if stateValue == "" || core.UTF16Len(stateValue) > 512 || binding == "" {
		return nil, core.NewIamError("OAUTH_STATE", "Missing login state.", 400)
	}
	saved, err := core.Transact(ctx, s.config.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		state, err := tx.Get(ctx, "oauthLoginStates", hash(stateValue))
		if err != nil {
			return nil, err
		}
		invalid := core.NewIamError("OAUTH_STATE", "Invalid, expired, or replayed login state.", 400)
		if state == nil || str(state, "connectionId") != connectionID || str(state, "tenantId") != item.TenantID {
			return nil, invalid
		}
		if expiresAt, _ := num(state, "expiresAt"); expiresAt <= float64(s.now()) {
			return nil, invalid
		}
		stored := []byte(str(state, "bindingHash"))
		presented := []byte(hash(binding))
		if len(stored) != len(presented) {
			return nil, &core.TypeError{Message: "Input buffers must have the same byte length"}
		}
		if subtle.ConstantTimeCompare(presented, stored) != 1 {
			return nil, invalid
		}
		if err := activeTenant(ctx, tx, item.TenantID); err != nil {
			return nil, err
		}
		if err := tx.Delete(ctx, "oauthLoginStates", str(state, "id")); err != nil {
			return nil, err
		}
		return state, nil
	})
	if err != nil {
		return nil, err
	}
	discovered, err := s.metadata(ctx, item)
	if err != nil {
		return nil, err
	}
	responseAS := discovered
	if item.Kind == "microsoft" {
		responseAS = discovered.Spread(core.NewObject("authorization_response_iss_parameter_supported", false))
	}
	if err := validateAuthResponse(responseAS, returnedParams, str(saved, "state")); err != nil {
		return nil, err
	}
	code, _ := returnedParams.get("code")
	if code == "" {
		return nil, ope(`no authorization code in "callbackParameters"`, "OAUTH_INVALID_RESPONSE")
	}
	tokenResponse, tokenBody, err := s.tokenRequest(ctx, discovered, item, code, str(saved, "codeVerifier"))
	if err != nil {
		return nil, err
	}
	// Entra multi-tenant metadata names the issuer as a template; resolve it for the directory that signed in.
	as := discovered
	if item.Kind == "microsoft" {
		if as, err = s.microsoftIssuer(item, discovered, tokenBody); err != nil {
			return nil, err
		}
	}
	openID := item.Kind != "github" && item.Kind != "oauth2"
	nonce := ""
	if openID {
		nonce = str(saved, "nonce")
	}
	result, claims, idToken, err := s.processTokenResponse(as, item, tokenResponse, tokenBody, openID, nonce)
	if err != nil {
		return nil, err
	}
	accessToken := str(result, "access_token")
	identity := core.NewObject("tenantId", item.TenantID, "providerId", item.ID)
	switch item.Kind {
	case "github":
		githubHeaders := map[string]string{"user-agent": "better-iam"}
		profileResponse, raw, err := s.resourceRequest(ctx, accessToken, "https://api.github.com/user", "application/vnd.github+json", githubHeaders)
		if err != nil {
			return nil, err
		}
		if !okStatus(profileResponse) {
			return nil, core.NewIamError("OAUTH_PROFILE", "Provider profile request failed.", 401)
		}
		profileValue, err := core.ParseJSON(raw)
		if err != nil {
			return nil, err
		}
		profile, _ := profileValue.(*core.Object)
		if profile == nil {
			profile = core.NewObject()
		}
		id := profile.Get("id")
		_, isNumber := id.(float64)
		_, isString := id.(string)
		if (!isNumber && !isString) || jsString(id) == "" {
			return nil, core.NewIamError("OAUTH_PROFILE", "Provider subject is missing.", 401)
		}
		identity.Set("issuer", "https://github.com")
		identity.Set("subject", jsString(id))
		if name, ok := profile.Get("name").(string); ok {
			identity.Set("name", name)
		} else if login, ok := profile.Get("login").(string); ok {
			identity.Set("name", login)
		} else {
			identity.Set("name", core.Undefined)
		}
		if err := s.mapAttributes(item, profile, identity); err != nil {
			return nil, err
		}
		emailResponse, raw, err := s.resourceRequest(ctx, accessToken, "https://api.github.com/user/emails", "application/vnd.github+json", githubHeaders)
		if err != nil {
			return nil, err
		}
		if okStatus(emailResponse) {
			emailsValue, err := core.ParseJSON(raw)
			if err != nil {
				return nil, err
			}
			if emails, ok := emailsValue.([]any); ok {
				for _, value := range emails {
					entry, ok := value.(*core.Object)
					if ok && entry != nil && entry.Get("primary") == true && entry.Get("verified") == true {
						if email, ok := entry.Get("email").(string); ok {
							identity.Set("email", email)
							identity.Set("emailVerified", true)
						}
						break
					}
				}
			}
		}
	case "oauth2":
		profileResponse, raw, err := s.resourceRequest(ctx, accessToken, item.UserInfoEndpoint, "application/json", nil)
		if err != nil {
			return nil, err
		}
		if !okStatus(profileResponse) {
			return nil, core.NewIamError("OAUTH_PROFILE", "Provider profile request failed.", 401)
		}
		profileValue, err := core.ParseJSON(raw)
		if err != nil {
			return nil, err
		}
		profile, ok := profileValue.(*core.Object)
		if !ok || profile == nil {
			return nil, core.NewIamError("OAUTH_PROFILE", "Provider profile is invalid.", 401)
		}
		mapped, err := item.MapProfile(profile)
		if err != nil {
			return nil, err
		}
		if mapped == nil || mapped.Subject == "" || core.UTF16Len(mapped.Subject) > 512 {
			return nil, core.NewIamError("OAUTH_PROFILE", "Provider subject is missing.", 401)
		}
		identity.Set("issuer", item.Issuer)
		identity.Set("subject", mapped.Subject)
		identity.Set("email", optionalString(mapped.Email))
		identity.Set("emailVerified", mapped.EmailVerified != nil && *mapped.EmailVerified)
		identity.Set("name", optionalString(mapped.Name))
		if err := s.mapAttributes(item, profile, identity); err != nil {
			return nil, err
		}
	default:
		if err := s.validateSignature(ctx, as, idToken); err != nil {
			return nil, err
		}
		if claims == nil || !truthy(claims.Get("sub")) {
			return nil, core.NewIamError("OAUTH_PROFILE", "OIDC subject is missing.", 401)
		}
		identity.Set("issuer", claims.Get("iss"))
		identity.Set("subject", claims.Get("sub"))
		if email, ok := claims.Get("email").(string); ok {
			identity.Set("email", email)
		} else {
			identity.Set("email", core.Undefined)
		}
		// Entra lets directory administrators set any email; only its verified-domain claim (xms_edov) counts.
		if item.Kind == "microsoft" {
			identity.Set("emailVerified", claims.Get("xms_edov") == true)
		} else {
			identity.Set("emailVerified", claims.Get("email_verified") == true)
		}
		if name, ok := claims.Get("name").(string); ok {
			identity.Set("name", name)
		} else {
			identity.Set("name", core.Undefined)
		}
		if err := s.mapAttributes(item, claims, identity); err != nil {
			return nil, err
		}
	}
	if err := activeTenant(ctx, s.config.Store, item.TenantID); err != nil {
		return nil, err
	}
	// Addresses outside the connection's enrollment domains never create an account.
	if item.AllowedEmailDomains != nil && identity.Get("emailVerified") == true {
		email := strings.ToLower(str(identity, "email"))
		allowed := false
		for _, domain := range item.AllowedEmailDomains {
			if str(identity, "email") != "" && strings.HasSuffix(email, "@"+strings.ToLower(domain)) {
				allowed = true
			}
		}
		if !allowed {
			identity.Set("emailVerified", false)
		}
	}
	if trust := item.TrustScimProvisioned; trust != nil && trust != false {
		if list, ok := trust.([]string); ok {
			identity.Set("trustScimProvisioned", anyList(list))
		} else {
			identity.Set("trustScimProvisioned", trust)
		}
	}
	if truthy(saved.Get("linkingSessionId")) && truthy(saved.Get("linkingIdentityId")) {
		identity.Set("linkingIdentityId", saved.Get("linkingIdentityId"))
		identity.Set("linkingSessionId", saved.Get("linkingSessionId"))
	}
	// Only protocol-verified claims reach this trusted server callback. It must apply local MFA.
	return s.config.CompleteAuthentication(ctx, identity)
}

func optionalString(value *string) any {
	if value == nil {
		return core.Undefined
	}
	return *value
}

func (s *OAuthLoginService) mapAttributes(item *OAuthLoginConnection, claims, identity *core.Object) error {
	if item.MapAttributes == nil {
		return nil
	}
	attributes, err := item.MapAttributes(claims)
	if err != nil {
		return err
	}
	if attributes != nil {
		identity.Set("attributes", attributes)
	}
	return nil
}

// validateAuthResponse is oauth4webapi validateAuthResponse.
func validateAuthResponse(as authorizationServer, params *searchParams, expectedState string) error {
	if value, ok := params.get("response"); ok && value != "" {
		return ope(`"parameters" contains a JARM response, use validateJwtAuthResponse() instead of validateAuthResponse()`, "OAUTH_INVALID_RESPONSE")
	}
	iss, hasIss := params.get("iss")
	state, hasState := params.get("state")
	if (!hasIss || iss == "") && truthy(as.Get("authorization_response_iss_parameter_supported")) {
		return ope(`response parameter "iss" (issuer) missing`, "OAUTH_INVALID_RESPONSE")
	}
	if hasIss && iss != "" && !jsEq(iss, as.Get("issuer")) {
		return ope(`unexpected "iss" (issuer) response parameter value`, "OAUTH_INVALID_RESPONSE")
	}
	if !hasState || state != expectedState {
		message := `unexpected "state" response parameter value`
		if !hasState {
			message = `response parameter "state" missing`
		}
		return ope(message, "OAUTH_INVALID_RESPONSE")
	}
	if value, ok := params.get("error"); ok && value != "" {
		return &oauthError{Code: "OAUTH_AUTHORIZATION_RESPONSE_ERROR", Message: "authorization response from the server is an error"}
	}
	_, idToken := params.get("id_token")
	_, token := params.get("token")
	if idToken || token {
		return &oauthError{Code: "OAUTH_UNSUPPORTED_OPERATION", Message: "implicit and hybrid flows are not supported"}
	}
	return nil
}

// cookieValue reads one cookie from a Cookie header (the TypeScript split-and-find).
func cookieValue(header, name string) string {
	for _, part := range strings.Split(header, ";") {
		part = core.JSTrim(part)
		if strings.HasPrefix(part, name+"=") {
			return part[len(name)+1:]
		}
	}
	return ""
}

func (s *OAuthLoginService) cookieName(item *OAuthLoginConnection) (string, bool) {
	redirect, _ := parseURL(item.RedirectURI)
	secure := redirect != nil && redirect.Protocol == "https:"
	prefix := ""
	if secure {
		prefix = "__Host-"
	}
	return prefix + "better-iam-oauth-" + hash(item.ID)[:12], secure
}

func errorCode(err error) (string, int) {
	var iam *core.IamError
	if errors.As(err, &iam) {
		return iam.Code, iam.Status
	}
	return "OAUTH_FAILED", 401
}

// Handler serves `{basePath}/{connectionId}` (begin: GET redirects, POST answers the URL for account linking) and
// each connection's callback URL; nil for every other request.
func (s *OAuthLoginService) Handler(ctx context.Context, request *http.Request) *Response {
	requestURL, err := parseURL(requestURL(request))
	if err != nil {
		return nil
	}
	var item *OAuthLoginConnection
	for _, id := range s.order {
		candidate := s.connections[id]
		target, err := parseURL(candidate.RedirectURI)
		if err == nil && urlOrigin(target) == urlOrigin(requestURL) && urlPathname(target) == urlPathname(requestURL) {
			item = candidate
			break
		}
	}
	if request.Method == http.MethodGet && item != nil {
		name, secure := s.cookieName(item)
		binding := cookieValue(request.Header.Get("cookie"), name)
		result, err := s.Callback(ctx, item.ID, requestURL.Href, binding)
		if err != nil {
			code, status := errorCode(err)
			return jsonResponse(status, core.NewObject("error", code), map[string]string{"cache-control": "no-store"})
		}
		secureAttribute := ""
		if secure {
			secureAttribute = "Secure; "
		}
		return jsonResponse(200, result, map[string]string{
			"cache-control": "no-store",
			"set-cookie":    name + "=; Path=/; HttpOnly; " + secureAttribute + "SameSite=Lax; Max-Age=0",
		})
	}
	pathname := urlPathname(requestURL)
	if !strings.HasPrefix(pathname, s.BasePath+"/") {
		return nil
	}
	if request.Method != http.MethodGet && request.Method != http.MethodPost {
		return jsonResponse(405, core.NewObject("error", "METHOD_NOT_ALLOWED"), nil)
	}
	fail := func(err error) *Response {
		code, status := errorCode(err)
		return jsonResponse(status, core.NewObject("error", code), nil)
	}
	id, ok := decodeURIComponent(pathname[len(s.BasePath)+1:])
	if !ok {
		return fail(errors.New("URIError: URI malformed"))
	}
	var linking *core.CredentialInput
	if request.Method == http.MethodPost {
		item, err := s.connection(id)
		if err != nil {
			return fail(err)
		}
		origin := request.Header.Get("origin")
		trusted := s.config.TrustedOrigins
		if trusted == nil {
			redirect, _ := parseURL(item.RedirectURI)
			trusted = []string{urlOrigin(redirect)}
		}
		if origin == "" || !contains(trusted, origin) || request.Header.Get("x-better-iam") != "1" ||
			!strings.HasPrefix(request.Header.Get("content-type"), "application/json") {
			return fail(core.NewIamError("CSRF", "Linking requires a trusted Origin and X-Better-IAM header.", 403))
		}
		linking = &core.CredentialInput{Headers: request.Header.Clone()}
	}
	query := newSearchParams(requestURL.RawQuery)
	loginHints := &LoginHints{}
	if value, _ := query.get("login_hint"); value != "" {
		loginHints.LoginHint = &value
	}
	if value, _ := query.get("domain_hint"); value != "" {
		loginHints.DomainHint = &value
	}
	if value, _ := query.get("prompt"); value != "" {
		loginHints.Prompt = &value
	}
	result, err := s.Begin(ctx, id, linking, loginHints)
	if err != nil {
		return fail(err)
	}
	connection, _ := s.connection(id)
	name, secure := s.cookieName(connection)
	secureAttribute := ""
	if secure {
		secureAttribute = "Secure; "
	}
	headers := map[string]string{
		"cache-control": "no-store",
		"set-cookie":    name + "=" + result.Binding + "; Path=/; HttpOnly; " + secureAttribute + "SameSite=Lax; Max-Age=600",
	}
	if request.Method == http.MethodPost {
		return jsonResponse(200, core.NewObject("url", result.URL), headers)
	}
	header := http.Header{}
	for key, value := range headers {
		header.Set(key, value)
	}
	header.Set("location", result.URL)
	return &Response{Status: 302, Header: header}
}
