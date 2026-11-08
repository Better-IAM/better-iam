package oauth

// Port of packages/oauth/src/provider.ts: the OAuth 2.0 / OpenID Connect authorization server. The TypeScript
// package configures `oidc-provider`; this port implements natively the oidc-provider features that configuration
// enables (provider_*.go): PKCE-only authorization code, rotating refresh tokens, client credentials, device
// authorization, pushed authorization requests, DPoP, resource indicators with JWT access tokens, introspection,
// revocation, RP-initiated and back-channel logout, dynamic registration and token exchange. Artifacts are stored
// in the oidc-provider payload format, sealed with the same key, so replicas of either implementation share them.

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// OAuthResourceServer is a protected API clients address with an RFC 8707 `resource` indicator.
type OAuthResourceServer struct {
	// Scopes this API understands; requested scopes outside this set are dropped from its access tokens.
	Scopes []string
	// Audience is the access token `aud`; defaults to the resource indicator.
	Audience string
	// AccessTokenTTL is the access token lifetime in seconds (default 900; 0 means unset).
	AccessTokenTTL *int64
	// AccessTokenFormat is jwt (default) or opaque.
	AccessTokenFormat string
}

// RegistrationPolicy is what dynamically registered clients of one tenant may be.
type RegistrationPolicy struct {
	TenantID string
	// Scopes the client may use (default `openid profile email offline_access`); nil means the default.
	Scopes []string
	// Resources the client may request tokens for.
	Resources []string
	// AllowConfidential allows confidential clients (a client secret).
	AllowConfidential bool
	// MaxClients caps anonymous registrations per tenant (default 100; nil means the default).
	MaxClients *int64
}

// AnonymousRegistrationRequest is what the anonymous registration hook sees.
type AnonymousRegistrationRequest struct {
	Headers http.Header
	IP      string
}

// RegistrationOptions enable dynamic client registration (RFC 7591).
type RegistrationOptions struct {
	// Anonymous maps a registration without a token to a tenant and its limits (nil declines it).
	Anonymous func(ctx context.Context, request AnonymousRegistrationRequest) (*RegistrationPolicy, error)
}

// TokenExchangeRequest is a token exchange the provider is about to perform.
type TokenExchangeRequest struct {
	TenantID string `json:"tenantId"`
	// ClientID is the client exchanging the token; it becomes the `act` (actor) of the issued token.
	ClientID string `json:"clientId"`
	// IdentityID is the account the subject token represents.
	IdentityID string `json:"identityId"`
	// SubjectClientID is the client the subject token was issued to.
	SubjectClientID string   `json:"subjectClientId"`
	SubjectScopes   []string `json:"subjectScopes"`
	Resource        string   `json:"resource"`
	Scopes          []string `json:"scopes"`
}

// DevicePageInput is what renderDevicePage receives.
type DevicePageInput struct {
	// Kind is input, confirm or success.
	Kind       string
	Form       string
	UserCode   string
	ClientName string
}

// OAuthProviderConfig configures createOAuthProvider.
type OAuthProviderConfig struct {
	Store  core.IamStore
	Issuer string
	// JWKS holds the private signing keys ({ keys: [...] }).
	JWKS       any
	CookieKeys []string
	// EncryptionKey is a base64 32-byte key, separate from signing keys, encrypting provider artifacts at rest.
	EncryptionKey string
	Authenticate  func(ctx context.Context, credential core.CredentialInput) (*auth.Principal, error)
	// ValidateSession applies the host's custom idle limits, email verification and MFA policy.
	ValidateSession func(ctx context.Context, sessionID string) error
	// LiveGrants are the groups and roles an identity holds right now, for the `iam` scope claims.
	LiveGrants func(ctx context.Context, identityID, tenantID string) (groupIDs []string, roleIDs []string, err error)
	// ClientAllowed is whether the person may get tokens for this client at all.
	ClientAllowed  func(ctx context.Context, identityID, tenantID, clientID string) (bool, error)
	Authorize      func(ctx context.Context, credential core.CredentialInput, action string, resource core.ResourceRef) error
	InteractionURL func(uid string) string
	// RenderDevicePage renders application-owned pages around the provider's CSRF-protected form markup.
	RenderDevicePage func(ctx context.Context, input DevicePageInput) (string, error)
	RenderLogoutPage func(ctx context.Context, form string) (string, error)
	TrustedOrigins   []string
	// Scopes are product-defined OAuth scopes; scopes are not IAM permission grants.
	Scopes []string
	// ResourceServers are protected APIs keyed by resource indicator.
	ResourceServers map[string]OAuthResourceServer
	// RequirePushedAuthorizationRequests rejects authorization requests that were not pushed first.
	RequirePushedAuthorizationRequests bool
	// DPoPNonceSecret is a base64 32-byte secret enabling server-provided DPoP nonces ("" disables them).
	DPoPNonceSecret string
	// AuthorizeTokenExchange adds policy for token exchange (RFC 8693); false refuses with access_denied.
	AuthorizeTokenExchange func(ctx context.Context, request TokenExchangeRequest) (bool, error)
	// Registration enables dynamic client registration (nil keeps it closed).
	Registration           *RegistrationOptions
	TrustProxy             bool
	AllowInsecureLocalhost bool
	// HTTPClient sends outbound requests (client JWKS URIs, back-channel logout).
	HTTPClient *http.Client
	// Now overrides the clock (epoch milliseconds).
	Now func() int64
}

// RegisterOAuthClient is registerClient's input.
type RegisterOAuthClient struct {
	OAuthClientSettings
	TenantID string
	ClientID string
	Public   bool
	// TokenEndpointAuthMethod is for confidential clients only; defaults to client_secret_basic.
	TokenEndpointAuthMethod string
	ServiceAccountID        string
}

// OAuthClientSettings are the client settings shared by registration and updates.
type OAuthClientSettings struct {
	Name         string
	RedirectURIs []string
	// GrantTypes nil means authorization_code and refresh_token.
	GrantTypes []string
	// Scopes nil means openid email profile offline_access.
	Scopes                     []string
	PostLogoutRedirectURIs     []string
	Resources                  []string
	RequireDPoP                bool
	RequirePushedAuthorization bool
	BackchannelLogoutURI       string
	// JWKS are the public keys of a private_key_jwt client (nil: unset).
	JWKS    any
	JWKSURI string
	// AccessTokenTTL is 60 to 86400 seconds (nil: provider default).
	AccessTokenTTL *int64
	// RefreshTokenTTL is 300 seconds to 30 days (nil: provider default).
	RefreshTokenTTL *int64
	LogoURI         string
	ClientURI       string
	PolicyURI       string
	TosURI          string
	FirstParty      bool
}

// UpdateOAuthClient is updateClient's input: nil members keep the current value; the Remove flags are `null`.
type UpdateOAuthClient struct {
	TenantID                   string
	ClientID                   string
	Name                       *string
	RedirectURIs               []string
	PostLogoutRedirectURIs     []string
	GrantTypes                 []string
	Scopes                     []string
	Resources                  []string
	RequireDPoP                *bool
	RequirePushedAuthorization *bool
	JWKS                       any
	JWKSURI                    *string
	BackchannelLogoutURI       *string
	RemoveBackchannelLogoutURI bool
	AccessTokenTTL             *int64
	RemoveAccessTokenTTL       bool
	RefreshTokenTTL            *int64
	RemoveRefreshTokenTTL      bool
	LogoURI                    *string
	RemoveLogoURI              bool
	ClientURI                  *string
	RemoveClientURI            bool
	PolicyURI                  *string
	RemovePolicyURI            bool
	TosURI                     *string
	RemoveTosURI               bool
	FirstParty                 *bool
}

// OAuthClientSummary is a registered client as administrators see it.
type OAuthClientSummary struct {
	ClientID                   string   `json:"clientId"`
	TenantID                   string   `json:"tenantId"`
	Name                       string   `json:"name"`
	Public                     bool     `json:"public"`
	RedirectURIs               []string `json:"redirectUris"`
	PostLogoutRedirectURIs     []string `json:"postLogoutRedirectUris"`
	GrantTypes                 []string `json:"grantTypes"`
	Scopes                     []string `json:"scopes"`
	Resources                  []string `json:"resources"`
	RequireDPoP                bool     `json:"requireDpop"`
	RequirePushedAuthorization bool     `json:"requirePushedAuthorization"`
	TokenEndpointAuthMethod    string   `json:"tokenEndpointAuthMethod"`
	BackchannelLogoutURI       string   `json:"backchannelLogoutUri,omitempty"`
	AccessTokenTTL             *float64 `json:"accessTokenTtl,omitempty"`
	RefreshTokenTTL            *float64 `json:"refreshTokenTtl,omitempty"`
	JWKSURI                    string   `json:"jwksUri,omitempty"`
	KeyIDs                     []string `json:"keyIds,omitempty"`
	ServiceAccountID           string   `json:"serviceAccountId,omitempty"`
	Revoked                    bool     `json:"revoked"`
	LogoURI                    string   `json:"logoUri,omitempty"`
	ClientURI                  string   `json:"clientUri,omitempty"`
	PolicyURI                  string   `json:"policyUri,omitempty"`
	TosURI                     string   `json:"tosUri,omitempty"`
	FirstParty                 bool     `json:"firstParty"`
	RegisteredVia              string   `json:"registeredVia,omitempty"`
	CreatedAt                  *float64 `json:"createdAt,omitempty"`
	UpdatedAt                  *float64 `json:"updatedAt,omitempty"`
	SecretRotatedAt            *float64 `json:"secretRotatedAt,omitempty"`
	// TokensRevoked is set by updateClient.
	TokensRevoked *bool `json:"tokensRevoked,omitempty"`
}

// OAuthGrantSummary is a consent an account gave a client ("connected app").
type OAuthGrantSummary struct {
	ID         string              `json:"id"`
	TenantID   string              `json:"tenantId"`
	IdentityID string              `json:"identityId"`
	ClientID   string              `json:"clientId"`
	ClientName string              `json:"clientName"`
	Scopes     []string            `json:"scopes"`
	Claims     []string            `json:"claims"`
	Resources  map[string][]string `json:"resources"`
	CreatedAt  float64             `json:"createdAt"`
	ExpiresAt  float64             `json:"expiresAt"`
}

// RegistrationTokenSummary is a tenant-scoped initial access token for dynamic client registration.
type RegistrationTokenSummary struct {
	ID                string   `json:"id"`
	TenantID          string   `json:"tenantId"`
	Name              string   `json:"name"`
	Scopes            []string `json:"scopes"`
	Resources         []string `json:"resources"`
	AllowConfidential bool     `json:"allowConfidential"`
	MaxClients        float64  `json:"maxClients"`
	Used              float64  `json:"used"`
	CreatedBy         string   `json:"createdBy"`
	CreatedAt         float64  `json:"createdAt"`
	ExpiresAt         float64  `json:"expiresAt"`
	Revoked           bool     `json:"revoked"`
	// Token is the token value, returned once by createRegistrationToken.
	Token string `json:"token,omitempty"`
}

var grantTypesSupported = []string{"authorization_code", "refresh_token", "client_credentials",
	"urn:ietf:params:oauth:grant-type:device_code", tokenExchangeGrant}

const (
	tokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange"
	accessTokenType    = "urn:ietf:params:oauth:token-type:access_token"
	deviceCodeGrant    = "urn:ietf:params:oauth:grant-type:device_code"
)

var (
	defaultRegistrationScopes = []string{"openid", "profile", "email", "offline_access"}
	scopeName                 = regexp.MustCompile(`^[a-zA-Z0-9:_.-]{1,128}$`)
	hex64                     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// registrationContext is what the registration gate decided for one `POST /reg`.
type registrationContext struct {
	tenantID          string
	scopes            []string
	resources         []string
	allowConfidential bool
	maxClients        int64
	tokenID           string
	actorID           string
}

// resourceServerInfo is a resolved resource server (oidc-provider's ResourceServer).
type resourceServerInfo struct {
	identifier     string
	scope          string
	audience       string
	accessTokenTTL int64
	format         string
}

func (r *resourceServerInfo) scopes() []string { return strings.Split(r.scope, " ") }

// Provider is createOAuthProvider's result.
type Provider struct {
	config          OAuthProviderConfig
	issuer          string
	issuerURL       *parsedURL
	BasePath        string
	crypt           *Cipher
	adapter         *ProviderAdapter
	resourceServers map[string]OAuthResourceServer
	resourceOrder   []string
	supportedScopes []string
	claimsSupported []string
	grantTypes      []string
	dpopNonces      *serverChallenge
	keys            *providerKeys
	cookieKeys      []string
	secure          bool
	now             func() int64
	httpClient      *http.Client
	clientCache     *clientCache
}

func (p *Provider) secureOrLocal(u *parsedURL) bool {
	return u.Protocol == "https:" || (p.config.AllowInsecureLocalhost && u.Protocol == "http:" && contains(loopbacks, u.Hostname))
}

// CreateOAuthProvider is createOAuthProvider.
func CreateOAuthProvider(config OAuthProviderConfig) (*Provider, error) {
	p := &Provider{config: config, issuer: config.Issuer, now: config.Now}
	if p.now == nil {
		p.now = wallNow
	}
	issuer, err := parseURL(config.Issuer)
	if err != nil {
		return nil, &core.TypeError{Message: "Invalid URL"}
	}
	p.issuerURL = issuer
	if urlHasSearch(issuer) || urlHasHash(issuer) || urlHasCredentials(issuer) || !p.secureOrLocal(issuer) {
		return nil, core.NewIamError("configuration", "OAuth issuer must use HTTPS.")
	}
	jwks, _ := core.Normalize(config.JWKS).(*core.Object)
	keyList, _ := get(jwks, "keys").([]any)
	shortKey := false
	for _, key := range config.CookieKeys {
		if core.UTF16Len(key) < 32 {
			shortKey = true
		}
	}
	if len(keyList) == 0 || len(config.CookieKeys) == 0 || shortKey || config.InteractionURL == nil ||
		config.RenderDevicePage == nil || config.RenderLogoutPage == nil || len(config.TrustedOrigins) == 0 {
		return nil, core.NewIamError("configuration", "OAuth provider signing keys, cookie keys, interaction callbacks, and trusted origins are required.")
	}
	key, err := EncryptionKey(config.EncryptionKey)
	if err != nil {
		return nil, err
	}
	if p.crypt, err = NewCipher(key); err != nil {
		return nil, err
	}
	p.resourceServers = map[string]OAuthResourceServer{}
	for indicator := range config.ResourceServers {
		p.resourceOrder = append(p.resourceOrder, indicator)
	}
	sort.Strings(p.resourceOrder)
	for _, indicator := range p.resourceOrder {
		server := config.ResourceServers[indicator]
		parsed, err := parseURL(indicator)
		if err != nil {
			return nil, core.NewIamError("configuration", "Resource indicators must be absolute URIs.")
		}
		if urlHasHash(parsed) || urlHasSearch(parsed) {
			return nil, core.NewIamError("configuration", "Resource indicators cannot carry a query or fragment (RFC 8707).")
		}
		invalid := len(server.Scopes) == 0
		for _, scope := range server.Scopes {
			if !scopeName.MatchString(scope) {
				invalid = true
			}
		}
		if server.AccessTokenTTL != nil && (*server.AccessTokenTTL <= 0 || *server.AccessTokenTTL > 9007199254740991) {
			invalid = true
		}
		if server.AccessTokenFormat != "" && server.AccessTokenFormat != "jwt" && server.AccessTokenFormat != "opaque" {
			invalid = true
		}
		if invalid {
			return nil, core.NewIamError("configuration", "Resource servers need scope identifiers, a positive integer TTL, and a jwt or opaque format.")
		}
		p.resourceServers[indicator] = server
	}
	scopes := []string{"openid", "email", "profile", "offline_access", "iam"}
	scopes = append(scopes, config.Scopes...)
	for _, indicator := range p.resourceOrder {
		scopes = append(scopes, p.resourceServers[indicator].Scopes...)
	}
	p.supportedScopes = unique(scopes)
	for _, scope := range p.supportedScopes {
		if !scopeName.MatchString(scope) {
			return nil, core.NewIamError("configuration", "OAuth scopes must be nonempty identifiers.")
		}
	}
	if config.DPoPNonceSecret != "" {
		secret := nodeBase64Decode(config.DPoPNonceSecret)
		if len(secret) != 32 {
			return nil, core.NewIamError("configuration", "dpopNonceSecret must encode exactly 32 bytes.")
		}
		p.dpopNonces = newServerChallenge(secret, "DPoP", p.now)
	}
	var register RegisterClientFunc
	if config.Registration != nil {
		register = p.storeRegisteredClient
	}
	adapter, err := CreateProviderAdapter(config.Store, config.EncryptionKey, config.ValidateSession, register)
	if err != nil {
		return nil, err
	}
	adapter.now = p.now
	p.adapter = adapter
	if p.keys, err = newProviderKeys(keyList); err != nil {
		return nil, err
	}
	p.cookieKeys = config.CookieKeys
	p.secure = issuer.Protocol == "https:"
	p.httpClient = config.HTTPClient
	if p.httpClient == nil {
		p.httpClient = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	p.clientCache = newClientCache()
	p.grantTypes = []string{"authorization_code", "refresh_token", "client_credentials", deviceCodeGrant, tokenExchangeGrant}
	p.claimsSupported = []string{"sub", "tenant_id", "email", "email_verified", "name", "roles", "groups", "attributes", "sid", "auth_time", "iss"}
	p.BasePath = strings.TrimSuffix(urlPathname(issuer), "/")
	return p, nil
}

// scopeClaims are the claims each scope exposes.
var scopeClaims = map[string][]string{
	"openid":  {"sub", "tenant_id"},
	"email":   {"email", "email_verified"},
	"profile": {"name"},
	// The `iam` scope exposes the account's current role and group IDs and declared attributes.
	"iam": {"roles", "groups", "attributes"},
}

func (p *Provider) grants() *ModelAdapter { return p.adapter.Model("Grant") }

// registrationLimits validates an anonymous-registration policy from the host.
func (p *Provider) registrationLimits(policy RegistrationPolicy) (*registrationContext, error) {
	scopes := policy.Scopes
	if scopes == nil {
		scopes = defaultRegistrationScopes
	}
	scopes = unique(scopes)
	resources := unique(append([]string{}, policy.Resources...))
	maxClients := int64(100)
	if policy.MaxClients != nil {
		maxClients = *policy.MaxClients
	}
	invalid := policy.TenantID == "" || len(scopes) == 0 || maxClients < 1 || maxClients > 100_000
	for _, scope := range scopes {
		if !contains(p.supportedScopes, scope) {
			invalid = true
		}
	}
	for _, indicator := range resources {
		if _, ok := p.resourceServers[indicator]; !ok {
			invalid = true
		}
	}
	if invalid {
		return nil, core.NewIamError("configuration", "Invalid dynamic registration policy.")
	}
	return &registrationContext{tenantID: policy.TenantID, scopes: scopes, resources: resources,
		allowConfidential: policy.AllowConfidential, maxClients: maxClients}, nil
}

func registrationTokenSummary(record *core.Object) *RegistrationTokenSummary {
	summary := &RegistrationTokenSummary{ID: str(record, "id"), TenantID: str(record, "tenantId"), Name: str(record, "name"),
		Scopes: nonNil(stringList(record.Get("scopes"))), Resources: nonNil(stringList(record.Get("resources"))),
		CreatedBy: str(record, "createdBy")}
	summary.AllowConfidential, _ = record.Get("allowConfidential").(bool)
	summary.MaxClients, _ = num(record, "maxClients")
	summary.Used, _ = num(record, "used")
	summary.CreatedAt, _ = num(record, "createdAt")
	summary.ExpiresAt, _ = num(record, "expiresAt")
	summary.Revoked, _ = record.Get("revoked").(bool)
	return summary
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func (p *Provider) usableRegistrationToken(record *core.Object) bool {
	revoked, _ := record.Get("revoked").(bool)
	expiresAt, _ := num(record, "expiresAt")
	used, _ := num(record, "used")
	maxClients, _ := num(record, "maxClients")
	return !revoked && expiresAt > float64(p.now()) && used < maxClients
}

// applyRegistrationPolicy applies the limits of a dynamic registration to the requested metadata.
func applyRegistrationPolicy(client *core.Object, registering *registrationContext) error {
	refuse := func(message string) error { return errInvalidClientMetadata(message) }
	client.Set("tenant_id", registering.tenantID)
	grantTypes := []any{"authorization_code"}
	if list, ok := client.Get("grant_types").([]any); ok {
		grantTypes = list
	}
	for _, grantType := range grantTypes {
		if grantType != "authorization_code" && grantType != "refresh_token" {
			return refuse("Registered clients may use only the authorization_code and refresh_token grants.")
		}
	}
	method := "client_secret_basic"
	if value := client.Get("token_endpoint_auth_method"); value != nil && !isUndefined(value) {
		method = jsString(value)
	}
	if method != "none" && !registering.allowConfidential {
		return refuse(`Only public clients (token_endpoint_auth_method "none") may register here.`)
	}
	if method != "none" && method != "client_secret_basic" && method != "client_secret_post" {
		return refuse("Unsupported token_endpoint_auth_method for dynamic registration.")
	}
	for _, key := range []string{"jwks", "jwks_uri", "sector_identifier_uri", "backchannel_logout_uri", "request_uris",
		"initiate_login_uri", "access_token_ttl", "refresh_token_ttl"} {
		if !isUndefined(client.Get(key)) {
			return refuse(key + " cannot be registered dynamically.")
		}
	}
	var uris []any
	if list, ok := client.Get("redirect_uris").([]any); ok {
		uris = append(uris, list...)
	}
	if list, ok := client.Get("post_logout_redirect_uris").([]any); ok {
		uris = append(uris, list...)
	}
	customScheme := regexp.MustCompile(`^[a-z][a-z0-9+-]*(\.[a-z0-9+-]+)+:$`)
	for _, uri := range uris {
		parsed, err := parseURL(jsString(uri))
		if err != nil {
			return refuse("Redirect URIs must be absolute.")
		}
		acceptable := !urlHasHash(parsed) && !urlHasCredentials(parsed) &&
			(parsed.Protocol == "https:" || (parsed.Protocol == "http:" && contains(loopbacks, parsed.Hostname)) ||
				customScheme.MatchString(parsed.Protocol))
		if !acceptable {
			return refuse("Redirect URIs must use HTTPS, loopback HTTP, or a reverse-domain custom scheme.")
		}
	}
	var requested []string
	if scope, ok := client.Get("scope").(string); ok {
		requested = splitFilter(scope)
	}
	if len(requested) == 0 {
		client.Set("scope", strings.Join(registering.scopes, " "))
	} else {
		for _, scope := range requested {
			if !contains(registering.scopes, scope) {
				return refuse("The requested scope is not allowed for this registration.")
			}
		}
	}
	return nil
}

// storeRegisteredClient persists a dynamically registered client inside the registration gate's tenant and limits.
func (p *Provider) storeRegisteredClient(ctx context.Context, clientID string, payload *core.Object) error {
	registering, _ := ctx.Value(registrationKey{}).(*registrationContext)
	if registering == nil || !jsEq(payload.Get("tenant_id"), registering.tenantID) {
		return core.NewIamError("PROTECTED_OPERATION", "Use authenticated registerClient().", 403)
	}
	return p.config.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		active, err := core.TenantTreeActive(ctx, tx, registering.tenantID)
		if err != nil {
			return err
		}
		if !active {
			return errAccessDenied("The tenant is unavailable.")
		}
		if registering.tokenID != "" {
			token, err := tx.Get(ctx, "oauthRegistrationTokens", registering.tokenID)
			if err != nil {
				return err
			}
			if token == nil || !p.usableRegistrationToken(token) {
				return errInvalidToken("The registration token is no longer usable.")
			}
			used, _ := num(token, "used")
			next := token.Clone()
			next.Set("used", used+1)
			if _, err := tx.Put(ctx, "oauthRegistrationTokens", next); err != nil {
				return err
			}
		} else {
			registered, err := tx.Find(ctx, "oauthClients", core.NewObject("tenantId", registering.tenantID, "registeredVia", "anonymous"), nil)
			if err != nil {
				return err
			}
			if int64(len(registered)) >= registering.maxClients {
				return errAccessDenied("The tenant has reached its registration limit.")
			}
		}
		existing, err := tx.Get(ctx, "oauthClients", hash(clientID))
		if err != nil {
			return err
		}
		if existing != nil {
			return errInvalidClientMetadata("The client ID is taken.")
		}
		now := p.now()
		via := registering.tokenID
		if via == "" {
			via = "anonymous"
		}
		if _, err := tx.Insert(ctx, "oauthClients", core.NewObject("id", hash(clientID), "tenantId", registering.tenantID,
			"clientId", clientID, "encrypted", p.crypt.Seal(payload), "revoked", false, "resources", anyList(registering.resources),
			"registeredVia", via, "createdAt", now, "updatedAt", now)); err != nil {
			return err
		}
		return p.audit(ctx, tx, registering.tenantID, registering.actorID, "iam:oauth:RegisterClient", clientID)
	})
}

type registrationKey struct{}

func (p *Provider) audit(ctx context.Context, tx core.IamStore, tenantID, actorID, action, resourceID string) error {
	_, err := core.AppendAuditEvent(ctx, tx, core.NewObject("id", randomUUID(), "tenantId", tenantID, "actorId", actorID,
		"action", action, "resourceId", resourceID, "timestamp", p.now(), "outcome", "allow"))
	return err
}

func (p *Provider) clientRow(ctx context.Context, clientID string) (*core.Object, error) {
	row, err := p.config.Store.Get(ctx, "oauthClients", hash(clientID))
	if err != nil {
		return nil, err
	}
	unavailable := core.NewIamError("OAUTH_CLIENT", "Client is unavailable.", 404)
	if row == nil || truthy(row.Get("revoked")) {
		return nil, unavailable
	}
	active, err := core.TenantTreeActive(ctx, p.config.Store, str(row, "tenantId"))
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, unavailable
	}
	return row, nil
}

// tenantClient is a client of tenantID, including revoked ones; foreign clients look like missing ones.
func (p *Provider) tenantClient(ctx context.Context, tx core.IamStore, tenantID, clientID string) (*core.Object, error) {
	var row *core.Object
	if clientID != "" {
		var err error
		if row, err = tx.Get(ctx, "oauthClients", hash(clientID)); err != nil {
			return nil, err
		}
	}
	if row == nil || str(row, "tenantId") != tenantID {
		return nil, core.NewIamError("NOT_FOUND", "Client not found.", 404)
	}
	return row, nil
}

func (p *Provider) summary(row *core.Object) (*OAuthClientSummary, error) {
	metadata, err := p.crypt.openObject(str(row, "encrypted"))
	if err != nil {
		return nil, err
	}
	name := row.Get("clientId")
	if value := metadata.Get("client_name"); value != nil && !isUndefined(value) {
		name = value
	}
	authMethod := "client_secret_basic"
	if value := metadata.Get("token_endpoint_auth_method"); value != nil && !isUndefined(value) {
		authMethod = jsString(value)
	}
	summary := &OAuthClientSummary{
		ClientID: str(row, "clientId"), TenantID: str(row, "tenantId"), Name: jsString(name),
		Public:                     metadata.Get("token_endpoint_auth_method") == "none",
		RedirectURIs:               nonNil(stringList(metadata.Get("redirect_uris"))),
		PostLogoutRedirectURIs:     nonNil(stringList(metadata.Get("post_logout_redirect_uris"))),
		GrantTypes:                 nonNil(stringList(metadata.Get("grant_types"))),
		Scopes:                     splitFilter(nullishString(metadata.Get("scope"))),
		Resources:                  nonNil(stringList(row.Get("resources"))),
		RequireDPoP:                metadata.Get("dpop_bound_access_tokens") == true,
		RequirePushedAuthorization: metadata.Get("require_pushed_authorization_requests") == true,
		TokenEndpointAuthMethod:    authMethod,
		BackchannelLogoutURI:       truthyString(metadata.Get("backchannel_logout_uri")),
		JWKSURI:                    truthyString(metadata.Get("jwks_uri")),
		ServiceAccountID:           truthyString(row.Get("serviceAccountId")),
		LogoURI:                    truthyString(metadata.Get("logo_uri")),
		ClientURI:                  truthyString(metadata.Get("client_uri")),
		PolicyURI:                  truthyString(metadata.Get("policy_uri")),
		TosURI:                     truthyString(metadata.Get("tos_uri")),
		FirstParty:                 row.Get("firstParty") == true,
		RegisteredVia:              truthyString(row.Get("registeredVia")),
	}
	summary.Revoked, _ = row.Get("revoked").(bool)
	if value, ok := metadata.Get("access_token_ttl").(float64); ok {
		summary.AccessTokenTTL = &value
	}
	if value, ok := metadata.Get("refresh_token_ttl").(float64); ok {
		summary.RefreshTokenTTL = &value
	}
	if jwks := obj(metadata, "jwks"); jwks != nil {
		summary.KeyIDs = []string{}
		for _, value := range get(jwks, "keys").([]any) {
			key, _ := value.(*core.Object)
			kid := get(key, "kid")
			if kid == nil || isUndefined(kid) {
				kid = get(key, "kty")
			}
			summary.KeyIDs = append(summary.KeyIDs, jsString(kid))
		}
	}
	for _, field := range []struct {
		key    string
		target **float64
	}{{"createdAt", &summary.CreatedAt}, {"updatedAt", &summary.UpdatedAt}, {"secretRotatedAt", &summary.SecretRotatedAt}} {
		if value, ok := num(row, field.key); ok && value != 0 {
			v := value
			*field.target = &v
		}
	}
	return summary, nil
}

// truthyString is the string form of a truthy value ("" otherwise).
func truthyString(value any) string {
	if !truthy(value) {
		return ""
	}
	return jsString(value)
}

type clientSettingsResult struct {
	metadata   *core.Object
	resources  []string
	firstParty bool
}

// settings validates client settings and returns the normalized protocol metadata (without identity or secret
// fields).
func (p *Provider) settings(input OAuthClientSettings, authMethod, serviceAccountID string) (*clientSettingsResult, error) {
	isPublic := authMethod == "none"
	if input.Name == "" || core.UTF16Len(input.Name) > 200 || input.RedirectURIs == nil || len(input.RedirectURIs) > 20 ||
		len(input.PostLogoutRedirectURIs) > 20 {
		return nil, core.NewIamError("INVALID_INPUT", "Invalid client configuration.")
	}
	for _, uri := range append(append([]string{}, input.RedirectURIs...), input.PostLogoutRedirectURIs...) {
		parsed, err := parseURL(uri)
		if err != nil {
			return nil, core.NewIamError("INVALID_INPUT", "Client redirect URIs must be absolute URLs.")
		}
		if urlHasHash(parsed) || urlHasCredentials(parsed) || !p.secureOrLocal(parsed) {
			return nil, core.NewIamError("INVALID_INPUT", "Client redirect URIs require HTTPS.")
		}
	}
	grantTypes := input.GrantTypes
	if grantTypes == nil {
		grantTypes = []string{"authorization_code", "refresh_token"}
	}
	invalidGrant := len(grantTypes) == 0
	for _, grantType := range grantTypes {
		if !contains(grantTypesSupported, grantType) {
			invalidGrant = true
		}
	}
	if isPublic && (contains(grantTypes, "client_credentials") || contains(grantTypes, tokenExchangeGrant)) {
		invalidGrant = true
	}
	if invalidGrant {
		return nil, core.NewIamError("INVALID_INPUT", "Unsupported client grant types.")
	}
	if contains(grantTypes, "authorization_code") && len(input.RedirectURIs) == 0 {
		return nil, core.NewIamError("INVALID_INPUT", "Authorization code clients need a redirect URI.")
	}
	scopes := input.Scopes
	if scopes == nil {
		scopes = []string{"openid", "email", "profile", "offline_access"}
	}
	for _, scope := range scopes {
		if !contains(p.supportedScopes, scope) {
			return nil, core.NewIamError("INVALID_INPUT", "Unsupported OAuth scope.")
		}
	}
	resources := unique(append([]string{}, input.Resources...))
	for _, indicator := range resources {
		if _, ok := p.resourceServers[indicator]; !ok {
			return nil, core.NewIamError("INVALID_INPUT", "Unknown resource indicator.")
		}
	}
	if contains(grantTypes, "client_credentials") && serviceAccountID == "" {
		return nil, core.NewIamError("INVALID_INPUT", "Client credentials require a tenant service account.")
	}
	secureURL := func(value, label string) error {
		parsed, err := parseURL(value)
		if err != nil {
			return core.NewIamError("INVALID_INPUT", label+" must be an absolute URL.")
		}
		if urlHasHash(parsed) || urlHasCredentials(parsed) || !p.secureOrLocal(parsed) {
			return core.NewIamError("INVALID_INPUT", label+" requires HTTPS.")
		}
		return nil
	}
	lifetime := func(value *int64, min, max int64) error {
		if value != nil && (*value < min || *value > max) {
			return core.NewIamError("INVALID_INPUT", " must be an integer from "+itoa(int(min))+" to "+itoa(int(max))+" seconds.")
		}
		return nil
	}
	if err := lifetime(input.AccessTokenTTL, 60, 86400); err != nil {
		return nil, err
	}
	if err := lifetime(input.RefreshTokenTTL, 300, 30*86400); err != nil {
		return nil, err
	}
	if input.BackchannelLogoutURI != "" {
		if err := secureURL(input.BackchannelLogoutURI, "The back-channel logout URI"); err != nil {
			return nil, err
		}
	}
	for _, item := range [][2]string{{input.LogoURI, "The logo URI"}, {input.ClientURI, "The client URI"},
		{input.PolicyURI, "The policy URI"}, {input.TosURI, "The terms of service URI"}} {
		if item[0] != "" {
			if err := secureURL(item[0], item[1]); err != nil {
				return nil, err
			}
		}
	}
	jwks, _ := core.Normalize(input.JWKS).(*core.Object)
	if input.JWKS != nil && jwks == nil {
		return nil, core.NewIamError("INVALID_INPUT", "jwks must hold one to ten public keys.")
	}
	if authMethod == "private_key_jwt" {
		if (jwks == nil) == (input.JWKSURI == "") {
			return nil, core.NewIamError("INVALID_INPUT", "private_key_jwt clients need either jwks or jwksUri.")
		}
		if input.JWKSURI != "" {
			if err := secureURL(input.JWKSURI, "The JWKS URI"); err != nil {
				return nil, err
			}
		}
		if jwks != nil {
			keys, ok := jwks.Get("keys").([]any)
			invalid := !ok || len(keys) == 0 || len(keys) > 10
			for _, value := range keys {
				key, ok := value.(*core.Object)
				if !ok || key == nil {
					invalid = true
					continue
				}
				if _, ok := key.Get("kty").(string); !ok {
					invalid = true
				}
				for _, member := range []string{"d", "p", "q", "dp", "dq", "qi", "k"} {
					if key.Has(member) {
						invalid = true
					}
				}
			}
			if invalid {
				return nil, core.NewIamError("INVALID_INPUT", "jwks must hold one to ten public keys.")
			}
		}
	} else if jwks != nil || input.JWKSURI != "" {
		return nil, core.NewIamError("INVALID_INPUT", "Only private_key_jwt clients register keys.")
	}
	responseTypes := []any{}
	if contains(grantTypes, "authorization_code") {
		responseTypes = []any{"code"}
	}
	metadata := core.NewObject("client_name", input.Name, "redirect_uris", anyList(input.RedirectURIs),
		"grant_types", anyList(grantTypes), "response_types", responseTypes, "scope", strings.Join(unique(scopes), " "),
		"post_logout_redirect_uris", anyList(nonNil(input.PostLogoutRedirectURIs)))
	if input.RequireDPoP {
		metadata.Set("dpop_bound_access_tokens", true)
	}
	if input.RequirePushedAuthorization {
		metadata.Set("require_pushed_authorization_requests", true)
	}
	if input.BackchannelLogoutURI != "" {
		metadata.Set("backchannel_logout_uri", input.BackchannelLogoutURI)
		metadata.Set("backchannel_logout_session_required", false)
	}
	for _, item := range [][2]string{{"logo_uri", input.LogoURI}, {"client_uri", input.ClientURI}, {"policy_uri", input.PolicyURI}, {"tos_uri", input.TosURI}} {
		if item[1] != "" {
			metadata.Set(item[0], item[1])
		}
	}
	if input.AccessTokenTTL != nil {
		metadata.Set("access_token_ttl", *input.AccessTokenTTL)
	}
	if input.RefreshTokenTTL != nil {
		metadata.Set("refresh_token_ttl", *input.RefreshTokenTTL)
	}
	if authMethod == "private_key_jwt" && jwks != nil {
		metadata.Set("jwks", jwks)
	}
	if authMethod == "private_key_jwt" && input.JWKSURI != "" {
		metadata.Set("jwks_uri", input.JWKSURI)
	}
	return &clientSettingsResult{metadata: metadata, resources: resources, firstParty: input.FirstParty}, nil
}

// purgeClientArtifacts deletes every artifact issued to a client (tokens, codes, grants).
func purgeClientArtifacts(ctx context.Context, tx core.IamStore, clientID string) error {
	rows, err := tx.Find(ctx, "oauthArtifacts", core.NewObject("clientId", clientID), nil)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if err := tx.Delete(ctx, "oauthArtifacts", str(row, "id")); err != nil {
			return err
		}
	}
	return nil
}

type grantOwnerResult struct {
	principal  *auth.Principal
	identityID string
}

// grantOwner is the account whose connected apps are read or changed.
func (p *Provider) grantOwner(ctx context.Context, credential core.CredentialInput, tenantID, identityID, action string) (*grantOwnerResult, error) {
	principal, err := p.config.Authenticate(ctx, credential)
	if err != nil {
		return nil, err
	}
	target := identityID
	if target == "" {
		target = str(principal.Identity, "id")
	}
	if target != str(principal.Identity, "id") || tenantID != str(principal.Identity, "tenantId") {
		if err := p.config.Authorize(ctx, credential, action, core.ResourceRef{TenantID: tenantID, Type: "iam", ID: target}); err != nil {
			return nil, err
		}
		identity, err := p.config.Store.Get(ctx, "identities", target)
		if err != nil {
			return nil, err
		}
		if identity == nil || str(identity, "tenantId") != tenantID {
			return nil, core.NewIamError("NOT_FOUND", "Identity not found.", 404)
		}
	}
	return &grantOwnerResult{principal: principal, identityID: target}, nil
}

type liveGrant struct {
	row     *core.Object
	grantID string
	summary *OAuthGrantSummary
}

// accountGrants are the live grants of an account: expired, revoked and session-orphaned grants are omitted.
func (p *Provider) accountGrants(ctx context.Context, tenantID, identityID string) ([]*liveGrant, error) {
	var live []*liveGrant
	names := map[string]string{}
	rows, err := p.config.Store.Find(ctx, "oauthArtifacts", core.NewObject("model", "Grant", "accountId", identityID), nil)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		expiresAt, _ := num(row, "expiresAt")
		clientID := truthyString(row.Get("clientId"))
		if str(row, "boundTenantId") != tenantID || expiresAt <= float64(p.now()) || clientID == "" {
			continue
		}
		sealed, err := p.crypt.openObject(str(row, "encrypted"))
		if err != nil {
			return nil, err
		}
		jti := truthyString(sealed.Get("jti"))
		if jti == "" {
			continue
		}
		payload, err := p.grants().Find(ctx, jti)
		if err != nil {
			return nil, err
		}
		if payload == nil {
			continue
		}
		if _, ok := names[clientID]; !ok {
			client, err := p.config.Store.Get(ctx, "oauthClients", hash(clientID))
			if err != nil {
				return nil, err
			}
			if client == nil || truthy(client.Get("revoked")) {
				continue
			}
			summary, err := p.summary(client)
			if err != nil {
				return nil, err
			}
			names[clientID] = summary.Name
		}
		openid := obj(payload, "openid")
		resources := map[string][]string{}
		obj(payload, "resources").Entries(func(indicator string, scope any) bool {
			resources[indicator] = splitFilter(jsString(scope))
			return true
		})
		claims := stringList(get(openid, "claims"))
		createdAt := 0.0
		if iat, ok := num(payload, "iat"); ok {
			createdAt = iat * 1000
		}
		live = append(live, &liveGrant{row: row, grantID: jti, summary: &OAuthGrantSummary{
			ID: str(row, "id"), TenantID: tenantID, IdentityID: identityID, ClientID: clientID, ClientName: names[clientID],
			Scopes: splitFilter(nullishString(get(openid, "scope"))), Claims: nonNil(claims), Resources: resources,
			CreatedAt: createdAt, ExpiresAt: expiresAt,
		}})
	}
	sort.SliceStable(live, func(i, j int) bool {
		a, b := live[i].summary, live[j].summary
		if a.CreatedAt != b.CreatedAt {
			return b.CreatedAt < a.CreatedAt
		}
		return a.ID < b.ID
	})
	return live, nil
}

func (p *Provider) revokeGrantIDs(ctx context.Context, principal *auth.Principal, tenantID string, revoked []*liveGrant) error {
	for _, grant := range revoked {
		if err := p.grants().RevokeByGrantID(ctx, grant.grantID); err != nil {
			return err
		}
	}
	if len(revoked) == 0 {
		return nil
	}
	return p.config.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		for _, grant := range revoked {
			if err := p.audit(ctx, tx, tenantID, str(principal.Identity, "id"), "iam:oauth:RevokeGrant", grant.summary.ClientID); err != nil {
				return err
			}
		}
		return nil
	})
}

// RegisteredClient is registerClient's result; a confidential client receives its secret once.
type RegisteredClient struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret,omitempty"`
	TenantID     string `json:"tenantId"`
}

// RegisterClient registers a tenant-bound client.
func (p *Provider) RegisterClient(ctx context.Context, credential core.CredentialInput, input RegisterOAuthClient) (*RegisteredClient, error) {
	if input.ClientID == "" || core.UTF16Len(input.ClientID) > 128 || input.Name == "" {
		return nil, core.NewIamError("INVALID_INPUT", "Invalid client configuration.")
	}
	authMethod := input.TokenEndpointAuthMethod
	if input.Public {
		authMethod = "none"
	} else if authMethod == "" {
		authMethod = "client_secret_basic"
	}
	if (input.Public && input.TokenEndpointAuthMethod != "") ||
		!contains([]string{"none", "client_secret_basic", "client_secret_post", "private_key_jwt"}, authMethod) {
		return nil, core.NewIamError("INVALID_INPUT", "Unsupported client authentication method.")
	}
	result, err := p.settings(input.OAuthClientSettings, authMethod, input.ServiceAccountID)
	if err != nil {
		return nil, err
	}
	secret := ""
	if strings.HasPrefix(authMethod, "client_secret_") {
		secret = randomB64URL(32)
	}
	metadata := core.NewObject("client_id", input.ClientID, "tenant_id", input.TenantID)
	if secret != "" {
		metadata.Set("client_secret", secret)
	} else {
		metadata.Set("client_secret", core.Undefined)
	}
	metadata.Set("token_endpoint_auth_method", authMethod)
	metadata.Assign(result.metadata)
	err = p.config.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		if err := p.config.Authorize(ctx, credential, "iam:oauth:clients:create", core.ResourceRef{TenantID: input.TenantID, Type: "oauth-client", ID: input.ClientID}); err != nil {
			return err
		}
		principal, err := p.config.Authenticate(ctx, credential)
		if err != nil {
			return err
		}
		active, err := core.TenantTreeActive(ctx, tx, input.TenantID)
		if err != nil {
			return err
		}
		if !active {
			return core.NewIamError("TENANT_INACTIVE", "Tenant is unavailable.", 403)
		}
		if input.ServiceAccountID != "" {
			service, err := tx.Get(ctx, "identities", input.ServiceAccountID)
			if err != nil {
				return err
			}
			if service == nil || str(service, "kind") != "service" || str(service, "status") != "active" || str(service, "tenantId") != input.TenantID {
				return core.NewIamError("INVALID_INPUT", "An active service account in the client tenant is required.")
			}
		}
		existing, err := tx.Get(ctx, "oauthClients", hash(input.ClientID))
		if err != nil {
			return err
		}
		if existing != nil {
			return core.NewIamError("CONFLICT", "Client ID already exists; tenant binding is immutable.", 409)
		}
		now := p.now()
		row := core.NewObject("id", hash(input.ClientID), "tenantId", input.TenantID, "clientId", input.ClientID,
			"encrypted", p.crypt.Seal(metadata), "revoked", false)
		if input.ServiceAccountID != "" {
			row.Set("serviceAccountId", input.ServiceAccountID)
		}
		row.Set("resources", anyList(result.resources))
		row.Set("firstParty", result.firstParty)
		row.Set("createdAt", now)
		row.Set("updatedAt", now)
		if _, err := tx.Insert(ctx, "oauthClients", row); err != nil {
			return err
		}
		if _, err := p.findClient(ctx, input.ClientID); err != nil {
			return err
		}
		return p.audit(ctx, tx, input.TenantID, str(principal.Identity, "id"), "iam:oauth:RegisterClient", input.ClientID)
	})
	if err != nil {
		return nil, err
	}
	return &RegisteredClient{ClientID: input.ClientID, ClientSecret: secret, TenantID: input.TenantID}, nil
}

// CreateRegistrationTokenInput is createRegistrationToken's input.
type CreateRegistrationTokenInput struct {
	TenantID string
	Name     string
	// ExpiresIn is the seconds until the token stops working (default 7 days, at most 1 year; nil: default).
	ExpiresIn         *int64
	MaxClients        *int64
	Scopes            []string
	Resources         []string
	AllowConfidential bool
}

// CreateRegistrationToken issues a tenant-scoped initial access token for dynamic client registration.
func (p *Provider) CreateRegistrationToken(ctx context.Context, credential core.CredentialInput, input CreateRegistrationTokenInput) (*RegistrationTokenSummary, error) {
	if p.config.Registration == nil {
		return nil, core.NewIamError("configuration", "Dynamic registration is not enabled.")
	}
	expiresIn := int64(7 * 86400)
	if input.ExpiresIn != nil {
		expiresIn = *input.ExpiresIn
	}
	if core.JSTrim(input.Name) == "" || core.UTF16Len(input.Name) > 200 || expiresIn < 60 || expiresIn > 365*86400 {
		return nil, core.NewIamError("INVALID_INPUT", "A name and a lifetime between one minute and one year are required.")
	}
	maxClients := int64(1)
	if input.MaxClients != nil {
		maxClients = *input.MaxClients
	}
	limits, err := p.registrationLimits(RegistrationPolicy{TenantID: input.TenantID, Scopes: input.Scopes, Resources: input.Resources,
		AllowConfidential: input.AllowConfidential, MaxClients: &maxClients})
	if err != nil {
		return nil, core.NewIamError("INVALID_INPUT", "Unsupported scopes, resources, or client limit.")
	}
	if err := p.config.Authorize(ctx, credential, "iam:oauth:clients:create", core.ResourceRef{TenantID: input.TenantID, Type: "oauth-client", ID: "*"}); err != nil {
		return nil, err
	}
	principal, err := p.config.Authenticate(ctx, credential)
	if err != nil {
		return nil, err
	}
	token := randomB64URL(32)
	now := p.now()
	record := core.NewObject("id", hash(token), "tenantId", input.TenantID, "name", core.JSTrim(input.Name),
		"scopes", anyList(limits.scopes), "resources", anyList(limits.resources), "allowConfidential", limits.allowConfidential,
		"maxClients", limits.maxClients, "used", 0, "createdBy", str(principal.Identity, "id"), "createdAt", now,
		"expiresAt", now+expiresIn*1000, "revoked", false)
	err = p.config.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		active, err := core.TenantTreeActive(ctx, tx, input.TenantID)
		if err != nil {
			return err
		}
		if !active {
			return core.NewIamError("TENANT_INACTIVE", "Tenant is unavailable.", 403)
		}
		if _, err := tx.Insert(ctx, "oauthRegistrationTokens", record); err != nil {
			return err
		}
		return p.audit(ctx, tx, input.TenantID, str(principal.Identity, "id"), "iam:oauth:CreateRegistrationToken", str(record, "id"))
	})
	if err != nil {
		return nil, err
	}
	summary := registrationTokenSummary(record)
	summary.Token = token
	return summary, nil
}

// ListRegistrationTokens lists a tenant's registration tokens without their values (`iam:oauth:clients:read`).
func (p *Provider) ListRegistrationTokens(ctx context.Context, credential core.CredentialInput, tenantID string) ([]*RegistrationTokenSummary, error) {
	if err := p.config.Authorize(ctx, credential, "iam:oauth:clients:read", core.ResourceRef{TenantID: tenantID, Type: "oauth-client", ID: "*"}); err != nil {
		return nil, err
	}
	records, err := p.config.Store.Find(ctx, "oauthRegistrationTokens", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(records, func(i, j int) bool {
		a, _ := num(records[i], "createdAt")
		b, _ := num(records[j], "createdAt")
		if a != b {
			return b < a
		}
		return str(records[i], "id") < str(records[j], "id")
	})
	out := make([]*RegistrationTokenSummary, 0, len(records))
	for _, record := range records {
		out = append(out, registrationTokenSummary(record))
	}
	return out, nil
}

// RevokeRegistrationToken stops a registration token; clients it registered stay (`iam:oauth:clients:delete`).
func (p *Provider) RevokeRegistrationToken(ctx context.Context, credential core.CredentialInput, tenantID, tokenID string) error {
	if err := p.config.Authorize(ctx, credential, "iam:oauth:clients:delete", core.ResourceRef{TenantID: tenantID, Type: "oauth-client", ID: "*"}); err != nil {
		return err
	}
	principal, err := p.config.Authenticate(ctx, credential)
	if err != nil {
		return err
	}
	return p.config.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		var record *core.Object
		if hex64.MatchString(tokenID) {
			if record, err = tx.Get(ctx, "oauthRegistrationTokens", tokenID); err != nil {
				return err
			}
		}
		if record == nil || str(record, "tenantId") != tenantID {
			return core.NewIamError("NOT_FOUND", "Registration token not found.", 404)
		}
		next := record.Clone()
		next.Set("revoked", true)
		if _, err := tx.Put(ctx, "oauthRegistrationTokens", next); err != nil {
			return err
		}
		return p.audit(ctx, tx, tenantID, str(principal.Identity, "id"), "iam:oauth:RevokeRegistrationToken", str(record, "id"))
	})
}

// ListClients lists the clients of a tenant the caller may read.
func (p *Provider) ListClients(ctx context.Context, credential core.CredentialInput, tenantID string, includeRevoked bool) ([]*OAuthClientSummary, error) {
	if _, err := p.config.Authenticate(ctx, credential); err != nil {
		return nil, err
	}
	rows, err := p.config.Store.Find(ctx, "oauthClients", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	visible := []*OAuthClientSummary{}
	for _, row := range rows {
		if truthy(row.Get("revoked")) && !includeRevoked {
			continue
		}
		if err := p.config.Authorize(ctx, credential, "iam:oauth:clients:read", core.ResourceRef{TenantID: tenantID, Type: "oauth-client", ID: str(row, "clientId")}); err != nil {
			var iam *core.IamError
			if errors.As(err, &iam) && (iam.Status == 403 || iam.Status == 404) {
				continue
			}
			return nil, err
		}
		summary, err := p.summary(row)
		if err != nil {
			return nil, err
		}
		visible = append(visible, summary)
	}
	sort.SliceStable(visible, func(i, j int) bool { return visible[i].ClientID < visible[j].ClientID })
	return visible, nil
}

// GetClient reads one client (`iam:oauth:clients:read`).
func (p *Provider) GetClient(ctx context.Context, credential core.CredentialInput, tenantID, clientID string) (*OAuthClientSummary, error) {
	if err := p.config.Authorize(ctx, credential, "iam:oauth:clients:read", core.ResourceRef{TenantID: tenantID, Type: "oauth-client", ID: clientID}); err != nil {
		return nil, err
	}
	row, err := p.tenantClient(ctx, p.config.Store, tenantID, clientID)
	if err != nil {
		return nil, err
	}
	return p.summary(row)
}

func narrowed(before, after []string) bool {
	for _, value := range before {
		if !contains(after, value) {
			return true
		}
	}
	return false
}

func pickString(value *string, remove bool, current string) string {
	if remove {
		return ""
	}
	if value != nil {
		return *value
	}
	return current
}

func pickTTL(value *int64, remove bool, current *float64) *int64 {
	if remove {
		return nil
	}
	if value != nil {
		return value
	}
	if current != nil {
		v := int64(*current)
		return &v
	}
	return nil
}

// UpdateClient changes client settings. Removing a grant type, scope or resource revokes every outstanding token,
// code and consent of the client.
func (p *Provider) UpdateClient(ctx context.Context, credential core.CredentialInput, input UpdateOAuthClient) (*OAuthClientSummary, error) {
	return core.Transact(ctx, p.config.Store, func(ctx context.Context, tx core.IamStore) (*OAuthClientSummary, error) {
		if err := p.config.Authorize(ctx, credential, "iam:oauth:clients:update", core.ResourceRef{TenantID: input.TenantID, Type: "oauth-client", ID: input.ClientID}); err != nil {
			return nil, err
		}
		principal, err := p.config.Authenticate(ctx, credential)
		if err != nil {
			return nil, err
		}
		row, err := p.tenantClient(ctx, tx, input.TenantID, input.ClientID)
		if err != nil {
			return nil, err
		}
		if truthy(row.Get("revoked")) {
			return nil, core.NewIamError("OAUTH_CLIENT", "Client is unavailable.", 404)
		}
		current, err := p.summary(row)
		if err != nil {
			return nil, err
		}
		pickList := func(value, fallback []string) []string {
			if value != nil {
				return value
			}
			return fallback
		}
		next := OAuthClientSettings{
			Name:                       pickString(input.Name, false, current.Name),
			RedirectURIs:               pickList(input.RedirectURIs, current.RedirectURIs),
			PostLogoutRedirectURIs:     pickList(input.PostLogoutRedirectURIs, current.PostLogoutRedirectURIs),
			GrantTypes:                 pickList(input.GrantTypes, current.GrantTypes),
			Scopes:                     pickList(input.Scopes, current.Scopes),
			Resources:                  pickList(input.Resources, current.Resources),
			RequireDPoP:                current.RequireDPoP,
			RequirePushedAuthorization: current.RequirePushedAuthorization,
			BackchannelLogoutURI:       pickString(input.BackchannelLogoutURI, input.RemoveBackchannelLogoutURI, current.BackchannelLogoutURI),
			AccessTokenTTL:             pickTTL(input.AccessTokenTTL, input.RemoveAccessTokenTTL, current.AccessTokenTTL),
			RefreshTokenTTL:            pickTTL(input.RefreshTokenTTL, input.RemoveRefreshTokenTTL, current.RefreshTokenTTL),
			LogoURI:                    pickString(input.LogoURI, input.RemoveLogoURI, current.LogoURI),
			ClientURI:                  pickString(input.ClientURI, input.RemoveClientURI, current.ClientURI),
			PolicyURI:                  pickString(input.PolicyURI, input.RemovePolicyURI, current.PolicyURI),
			TosURI:                     pickString(input.TosURI, input.RemoveTosURI, current.TosURI),
			FirstParty:                 current.FirstParty,
		}
		if input.RequireDPoP != nil {
			next.RequireDPoP = *input.RequireDPoP
		}
		if input.RequirePushedAuthorization != nil {
			next.RequirePushedAuthorization = *input.RequirePushedAuthorization
		}
		if input.FirstParty != nil {
			next.FirstParty = *input.FirstParty
		}
		previous, err := p.crypt.openObject(str(row, "encrypted"))
		if err != nil {
			return nil, err
		}
		// Signing keys: new inline keys or a new URL replace whichever the client had.
		switch {
		case input.JWKS != nil:
			next.JWKS = input.JWKS
		case input.JWKSURI != nil:
			next.JWKSURI = *input.JWKSURI
		case truthy(previous.Get("jwks")):
			next.JWKS = previous.Get("jwks")
		case truthy(previous.Get("jwks_uri")):
			next.JWKSURI = jsString(previous.Get("jwks_uri"))
		}
		result, err := p.settings(next, current.TokenEndpointAuthMethod, truthyString(row.Get("serviceAccountId")))
		if err != nil {
			return nil, err
		}
		metadata := core.NewObject("client_id", previous.Get("client_id"), "tenant_id", previous.Get("tenant_id"),
			"client_secret", previous.Get("client_secret"), "token_endpoint_auth_method", previous.Get("token_endpoint_auth_method"))
		metadata.Assign(result.metadata)
		tokensRevoked := narrowed(current.GrantTypes, next.GrantTypes) || narrowed(current.Scopes, next.Scopes) ||
			narrowed(current.Resources, result.resources) || (!current.RequireDPoP && next.RequireDPoP)
		updated := row.Clone()
		updated.Set("encrypted", p.crypt.Seal(metadata))
		updated.Set("resources", anyList(result.resources))
		updated.Set("firstParty", result.firstParty)
		updated.Set("updatedAt", p.now())
		if _, err := tx.Put(ctx, "oauthClients", updated); err != nil {
			return nil, err
		}
		if tokensRevoked {
			if err := purgeClientArtifacts(ctx, tx, str(row, "clientId")); err != nil {
				return nil, err
			}
		}
		if err := p.audit(ctx, tx, input.TenantID, str(principal.Identity, "id"), "iam:oauth:UpdateClient", input.ClientID); err != nil {
			return nil, err
		}
		stored, err := tx.Get(ctx, "oauthClients", str(row, "id"))
		if err != nil {
			return nil, err
		}
		summary, err := p.summary(stored)
		if err != nil {
			return nil, err
		}
		summary.TokensRevoked = boolPtr(tokensRevoked)
		return summary, nil
	})
}

// RotateClientSecret replaces a confidential client's secret; revokeTokens also invalidates everything issued to it.
func (p *Provider) RotateClientSecret(ctx context.Context, credential core.CredentialInput, tenantID, clientID string, revokeTokens bool) (*RegisteredClient, error) {
	secret := randomB64URL(32)
	err := p.config.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		if err := p.config.Authorize(ctx, credential, "iam:oauth:clients:update", core.ResourceRef{TenantID: tenantID, Type: "oauth-client", ID: clientID}); err != nil {
			return err
		}
		principal, err := p.config.Authenticate(ctx, credential)
		if err != nil {
			return err
		}
		row, err := p.tenantClient(ctx, tx, tenantID, clientID)
		if err != nil {
			return err
		}
		if truthy(row.Get("revoked")) {
			return core.NewIamError("OAUTH_CLIENT", "Client is unavailable.", 404)
		}
		metadata, err := p.crypt.openObject(str(row, "encrypted"))
		if err != nil {
			return err
		}
		if !strings.HasPrefix(jsString(metadata.Get("token_endpoint_auth_method")), "client_secret_") {
			return core.NewIamError("INVALID_INPUT", "Only secret-authenticated clients have a secret.")
		}
		now := p.now()
		updated := row.Clone()
		metadata.Set("client_secret", secret)
		updated.Set("encrypted", p.crypt.Seal(metadata))
		updated.Set("updatedAt", now)
		updated.Set("secretRotatedAt", now)
		if _, err := tx.Put(ctx, "oauthClients", updated); err != nil {
			return err
		}
		if revokeTokens {
			if err := purgeClientArtifacts(ctx, tx, str(row, "clientId")); err != nil {
				return err
			}
		}
		return p.audit(ctx, tx, tenantID, str(principal.Identity, "id"), "iam:oauth:RotateClientSecret", clientID)
	})
	if err != nil {
		return nil, err
	}
	return &RegisteredClient{ClientID: clientID, ClientSecret: secret, TenantID: tenantID}, nil
}

// RevokeClient revokes a client and everything issued to it.
func (p *Provider) RevokeClient(ctx context.Context, credential core.CredentialInput, tenantID, clientID string) error {
	return p.config.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		if err := p.config.Authorize(ctx, credential, "iam:oauth:clients:delete", core.ResourceRef{TenantID: tenantID, Type: "oauth-client", ID: clientID}); err != nil {
			return err
		}
		principal, err := p.config.Authenticate(ctx, credential)
		if err != nil {
			return err
		}
		row, err := p.clientRow(ctx, clientID)
		if err != nil {
			return err
		}
		if str(row, "tenantId") != tenantID {
			return core.NewIamError("NOT_FOUND", "Client not found.", 404)
		}
		updated := row.Clone()
		updated.Set("revoked", true)
		updated.Set("updatedAt", p.now())
		if _, err := tx.Put(ctx, "oauthClients", updated); err != nil {
			return err
		}
		if err := purgeClientArtifacts(ctx, tx, clientID); err != nil {
			return err
		}
		return p.audit(ctx, tx, tenantID, str(principal.Identity, "id"), "iam:oauth:RevokeClient", clientID)
	})
}

// ListGrants lists the live consents of an account (the caller's own without identityID).
func (p *Provider) ListGrants(ctx context.Context, credential core.CredentialInput, tenantID, identityID, clientID string) ([]*OAuthGrantSummary, error) {
	owner, err := p.grantOwner(ctx, credential, tenantID, identityID, "iam:oauth:grants:read")
	if err != nil {
		return nil, err
	}
	grants, err := p.accountGrants(ctx, tenantID, owner.identityID)
	if err != nil {
		return nil, err
	}
	out := []*OAuthGrantSummary{}
	for _, grant := range grants {
		if clientID == "" || grant.summary.ClientID == clientID {
			out = append(out, grant.summary)
		}
	}
	return out, nil
}

// RevokeGrant revokes one consent by its OAuthGrantSummary.ID, with every token and code issued under it.
func (p *Provider) RevokeGrant(ctx context.Context, credential core.CredentialInput, tenantID, grantID string) error {
	var row *core.Object
	if hex64.MatchString(grantID) {
		var err error
		if row, err = p.config.Store.Get(ctx, "oauthArtifacts", grantID); err != nil {
			return err
		}
	}
	principal, err := p.config.Authenticate(ctx, credential)
	if err != nil {
		return err
	}
	identityID := ""
	if row != nil && str(row, "model") == "Grant" && str(row, "boundTenantId") == tenantID {
		identityID = truthyString(row.Get("accountId"))
	}
	// Unknown references and foreign grants look the same; authorization runs before disclosure.
	target := identityID
	if target == "" {
		target = str(principal.Identity, "id")
	}
	owner, err := p.grantOwner(ctx, credential, tenantID, target, "iam:oauth:grants:revoke")
	if err != nil {
		return err
	}
	var grant *liveGrant
	if identityID != "" {
		grants, err := p.accountGrants(ctx, tenantID, owner.identityID)
		if err != nil {
			return err
		}
		for _, candidate := range grants {
			if str(candidate.row, "id") == grantID {
				grant = candidate
				break
			}
		}
	}
	if grant == nil {
		return core.NewIamError("NOT_FOUND", "Grant not found.", 404)
	}
	return p.revokeGrantIDs(ctx, owner.principal, tenantID, []*liveGrant{grant})
}

// RevokeGrants disconnects apps: every consent of an account, optionally only for one client.
func (p *Provider) RevokeGrants(ctx context.Context, credential core.CredentialInput, tenantID, identityID, clientID string) (int, error) {
	owner, err := p.grantOwner(ctx, credential, tenantID, identityID, "iam:oauth:grants:revoke")
	if err != nil {
		return 0, err
	}
	grants, err := p.accountGrants(ctx, tenantID, owner.identityID)
	if err != nil {
		return 0, err
	}
	var matching []*liveGrant
	for _, grant := range grants {
		if clientID == "" || grant.summary.ClientID == clientID {
			matching = append(matching, grant)
		}
	}
	if err := p.revokeGrantIDs(ctx, owner.principal, tenantID, matching); err != nil {
		return 0, err
	}
	return len(matching), nil
}

// LogoutFailure is a back-channel logout that could not be delivered.
type LogoutFailure struct {
	ClientID   string `json:"clientId"`
	IdentityID string `json:"identityId"`
}

// LogoutResult is logoutEndedSessions's result.
type LogoutResult struct {
	Sessions int             `json:"sessions"`
	Grants   int             `json:"grants"`
	Notified int             `json:"notified"`
	Failures []LogoutFailure `json:"failures"`
}

// LogoutEndedSessions revokes every consent bound to an ended IAM session and sends back-channel logout tokens.
func (p *Provider) LogoutEndedSessions(ctx context.Context, identityID string) (*LogoutResult, error) {
	var filter *core.Object
	if identityID != "" {
		filter = core.NewObject("identityId", identityID)
	}
	bindings, err := p.config.Store.Find(ctx, "oauthGrantSessions", filter, nil)
	if err != nil {
		return nil, err
	}
	ended := map[string]*core.Object{}
	var endedOrder []string
	sessionEnded := map[string]bool{}
	checked := map[string]bool{}
	for _, binding := range bindings {
		sessionID := str(binding, "sessionId")
		if !checked[sessionID] {
			checked[sessionID] = true
			session, err := p.config.Store.Get(ctx, "sessions", sessionID)
			if err != nil {
				return nil, err
			}
			identity, err := p.config.Store.Get(ctx, "identities", str(binding, "identityId"))
			if err != nil {
				return nil, err
			}
			live := session != nil && identity != nil && jsEq(session.Get("identityId"), binding.Get("identityId")) &&
				jsEq(session.Get("tenantId"), binding.Get("tenantId")) && str(identity, "status") == "active"
			if live {
				expiresAt, _ := num(session, "expiresAt")
				live = expiresAt > float64(p.now())
			}
			if live {
				if live, err = core.TenantTreeActive(ctx, p.config.Store, str(binding, "tenantId")); err != nil {
					return nil, err
				}
			}
			if live && p.config.ValidateSession != nil {
				live = p.config.ValidateSession(ctx, sessionID) == nil
			}
			sessionEnded[sessionID] = !live
		}
		if sessionEnded[sessionID] {
			if _, ok := ended[str(binding, "id")]; !ok {
				endedOrder = append(endedOrder, str(binding, "id"))
			}
			ended[str(binding, "id")] = binding
		}
	}
	if len(ended) == 0 {
		return &LogoutResult{Failures: []LogoutFailure{}}, nil
	}
	type revokedGrant struct {
		grantID, clientID string
		binding           *core.Object
	}
	var revoked []revokedGrant
	seenIdentities := map[string]bool{}
	for _, id := range endedOrder {
		identity := str(ended[id], "identityId")
		if seenIdentities[identity] {
			continue
		}
		seenIdentities[identity] = true
		rows, err := p.config.Store.Find(ctx, "oauthArtifacts", core.NewObject("model", "Grant", "accountId", identity), nil)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			sealed, err := p.crypt.openObject(str(row, "encrypted"))
			if err != nil {
				return nil, err
			}
			jti := truthyString(sealed.Get("jti"))
			if jti == "" {
				continue
			}
			if binding := ended[hash(jti)]; binding != nil && truthy(row.Get("clientId")) {
				revoked = append(revoked, revokedGrant{grantID: jti, clientID: jsString(row.Get("clientId")), binding: binding})
			}
		}
	}
	notified := 0
	failures := []LogoutFailure{}
	var informed []string
	informedSet := map[string]bool{}
	for _, grant := range revoked {
		key := grant.clientID + "\n" + str(grant.binding, "identityId")
		if informedSet[key] {
			continue
		}
		informedSet[key] = true
		informed = append(informed, key)
		client, err := p.findClient(ctx, grant.clientID)
		if err != nil || client == nil || client.backchannelLogoutURI() == "" {
			continue
		}
		// The logout token is signed with the provider keys and POSTed to the client.
		if err := p.backchannelLogout(ctx, client, str(grant.binding, "identityId"), ""); err != nil {
			failures = append(failures, LogoutFailure{ClientID: grant.clientID, IdentityID: str(grant.binding, "identityId")})
		} else {
			notified++
		}
	}
	for _, grant := range revoked {
		if err := p.grants().RevokeByGrantID(ctx, grant.grantID); err != nil {
			return nil, err
		}
	}
	err = p.config.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		for _, id := range endedOrder {
			if err := tx.Delete(ctx, "oauthGrantSessions", str(ended[id], "id")); err != nil {
				return err
			}
		}
		for _, key := range informed {
			parts := strings.SplitN(key, "\n", 2)
			var binding *core.Object
			for _, id := range endedOrder {
				if str(ended[id], "identityId") == parts[1] {
					binding = ended[id]
					break
				}
			}
			if err := p.audit(ctx, tx, str(binding, "tenantId"), parts[1], "iam:oauth:SessionLogout", parts[0]); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sessions := map[string]bool{}
	for _, id := range endedOrder {
		sessions[str(ended[id], "sessionId")] = true
	}
	return &LogoutResult{Sessions: len(sessions), Grants: len(revoked), Notified: notified, Failures: failures}, nil
}
