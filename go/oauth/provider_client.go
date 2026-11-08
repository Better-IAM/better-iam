package oauth

// The provider's client model: oidc-provider's Client schema validation (helpers/client_schema.js) for the metadata
// the provider stores, client keystores for private_key_jwt (inline jwks or a refreshed jwks_uri), and back-channel
// logout delivery (models/client.js).

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

var recognizedMetadata = []string{
	"application_type", "client_id_issued_at", "client_id", "client_name", "client_secret_expires_at", "client_secret",
	"client_uri", "contacts", "default_acr_values", "default_max_age", "grant_types", "id_token_signed_response_alg",
	"initiate_login_uri", "jwks_uri", "jwks", "logo_uri", "policy_uri", "redirect_uris", "require_auth_time",
	"response_types", "response_modes", "scope", "sector_identifier_uri", "subject_type", "token_endpoint_auth_method",
	"tos_uri", "token_endpoint_auth_signing_alg", "post_logout_redirect_uris", "backchannel_logout_session_required",
	"backchannel_logout_uri", "require_pushed_authorization_requests", "dpop_bound_access_tokens",
}

var extraClientProperties = []string{"tenant_id", "access_token_ttl", "refresh_token_ttl"}

var clientDefaults = core.NewObject(
	"application_type", "web", "grant_types", []any{"authorization_code"}, "id_token_signed_response_alg", "RS256",
	"require_auth_time", false, "response_types", []any{"code"}, "subject_type", "public",
	"token_endpoint_auth_method", "client_secret_basic", "post_logout_redirect_uris", []any{},
	"backchannel_logout_session_required", false, "require_pushed_authorization_requests", false,
	"dpop_bound_access_tokens", false,
)

var (
	booleanMetadata = []string{"backchannel_logout_session_required", "dpop_bound_access_tokens", "require_auth_time", "require_pushed_authorization_requests"}
	arrayMetadata   = []string{"contacts", "default_acr_values", "grant_types", "post_logout_redirect_uris", "redirect_uris", "response_types", "response_modes"}
	stringMetadata  = []string{"application_type", "backchannel_logout_uri", "client_id", "client_name", "client_secret", "client_uri",
		"id_token_signed_response_alg", "initiate_login_uri", "jwks_uri", "logo_uri", "policy_uri", "scope", "sector_identifier_uri",
		"subject_type", "token_endpoint_auth_method", "tos_uri", "token_endpoint_auth_signing_alg",
		"contacts", "default_acr_values", "grant_types", "post_logout_redirect_uris", "redirect_uris", "response_types", "response_modes"}
	webURIMetadata       = []string{"backchannel_logout_uri", "client_uri", "initiate_login_uri", "jwks_uri", "logo_uri", "policy_uri", "sector_identifier_uri", "tos_uri"}
	httpsURIMetadata     = []string{"initiate_login_uri", "sector_identifier_uri"}
	clientAuthMethods    = []string{"client_secret_basic", "client_secret_jwt", "client_secret_post", "private_key_jwt", "none"}
	clientAuthAlgs       = []string{"HS256", "RS256", "PS256", "ES256", "Ed25519", "EdDSA"}
	idTokenSigningAlgs   = []string{"RS256", "PS256", "ES256", "Ed25519", "EdDSA"}
	dpopSigningAlgs      = []string{"ES256", "Ed25519", "EdDSA"}
	nonSecretMethods     = []string{"private_key_jwt", "none", "tls_client_auth", "self_signed_tls_client_auth", "attest_jwt_client_auth"}
	noVSChar             = regexp.MustCompile(`[^\x20-\x7E]`)
	contactPattern       = regexp.MustCompile("^[a-zA-Z0-9.!#$%&’*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)*$")
	forbiddenSchemes     = []string{"javascript:", "vbscript:", "data:", "blob:", "file:", "about:"}
	responseModesHandled = []string{"query", "fragment", "form_post"}
)

// formatList is helpers/formatters.js formatList: 'a', 'b', and 'c' (or 'or').
func formatList(values []string, disjunction bool) string {
	quoted := make([]string, len(values))
	for index, value := range values {
		quoted[index] = "'" + value + "'"
	}
	word := "and"
	if disjunction {
		word = "or"
	}
	switch len(quoted) {
	case 0:
		return ""
	case 1:
		return quoted[0]
	case 2:
		return quoted[0] + " " + word + " " + quoted[1]
	}
	return strings.Join(quoted[:len(quoted)-1], ", ") + ", " + word + " " + quoted[len(quoted)-1]
}

func pluralize(word string, count int) string {
	if count == 1 {
		return word
	}
	return word + "s"
}

// isWebURI is valid_url.js isWebUri.
func isWebURI(value any) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	parsed, err := parseURL(text)
	return err == nil && (parsed.Protocol == "https:" || parsed.Protocol == "http:")
}

func isHTTPSURI(value any) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	parsed, err := parseURL(text)
	return err == nil && parsed.Protocol == "https:"
}

// clientSchema validates and normalizes client metadata (new Client.Schema(metadata, ctx)).
func (p *Provider) clientSchema(ctx context.Context, metadata *core.Object) (*core.Object, error) {
	schema := core.NewObject()
	for _, key := range recognizedMetadata {
		if value := clientDefaults.Get(key); !isUndefined(value) {
			schema.Set(key, core.CloneValue(value))
		}
	}
	if p.config.RequirePushedAuthorizationRequests {
		// parPolicy forces the flag (applied after validation as well).
	}
	for _, key := range append(append([]string{}, recognizedMetadata...), extraClientProperties...) {
		if value := metadata.Get(key); !isUndefined(value) {
			schema.Set(key, core.CloneValue(value))
		}
	}
	// processCustomMetadata: the extraClientMetadata validator runs for each extra property.
	registering, _ := ctx.Value(registrationKey{}).(*registrationContext)
	for _, key := range extraClientProperties {
		value := schema.Get(key)
		if key == "tenant_id" && registering != nil {
			if err := applyRegistrationPolicy(schema, registering); err != nil {
				return nil, err
			}
			continue
		}
		if key == "tenant_id" {
			if text, ok := value.(string); !ok || text == "" {
				return nil, errInvalidClientMetadata("tenant_id is required.")
			}
			continue
		}
		if !isUndefined(value) && !isSafeInteger(value) {
			return nil, errInvalidClientMetadata(key + " must be an integer.")
		}
	}
	invalidate := func(message string) (*core.Object, error) { return nil, errInvalidClientMetadata(message) }
	// required
	required := []string{"client_id"}
	if clientNeedsSecret(schema) {
		required = append(required, "client_secret")
	}
	if list, ok := schema.Get("response_types").([]any); ok && len(list) > 0 {
		required = append(required, "redirect_uris")
	} else if isUndefined(schema.Get("redirect_uris")) {
		schema.Set("redirect_uris", []any{})
	}
	for _, prop := range required {
		if !truthy(schema.Get(prop)) {
			return invalidate(prop + " is mandatory property")
		}
	}
	method := str(schema, "token_endpoint_auth_method")
	if (method == "private_key_jwt" || method == "self_signed_tls_client_auth") && !truthy(schema.Get("jwks")) && !truthy(schema.Get("jwks_uri")) {
		return invalidate("jwks or jwks_uri is mandatory for this client")
	}
	for _, prop := range booleanMetadata {
		if value := schema.Get(prop); !isUndefined(value) {
			if _, ok := value.(bool); !ok {
				return invalidate(prop + " must be a boolean")
			}
		}
	}
	for _, prop := range arrayMetadata {
		if value := schema.Get(prop); !isUndefined(value) {
			list, ok := value.([]any)
			if !ok {
				return invalidate(prop + " must be an array")
			}
			seen := []any{}
			for _, item := range list {
				duplicate := false
				for _, existing := range seen {
					if core.StrictEquals(existing, item) {
						duplicate = true
					}
				}
				if !duplicate {
					seen = append(seen, item)
				}
			}
			schema.Set(prop, seen)
		}
	}
	for _, prop := range stringMetadata {
		value := schema.Get(prop)
		if isUndefined(value) {
			continue
		}
		isArray := contains(arrayMetadata, prop)
		items := []any{value}
		if isArray {
			items, _ = value.([]any)
		}
		for _, item := range items {
			if text, ok := item.(string); !ok || text == "" {
				if isArray {
					return invalidate(prop + " must only contain strings")
				}
				return invalidate(prop + " must be a non-empty string if provided")
			}
		}
	}
	for _, prop := range []string{"client_id", "client_secret"} {
		if text, ok := schema.Get(prop).(string); ok && noVSChar.MatchString(text) {
			return invalidate("invalid " + prop + " value")
		}
	}
	responseTypes := []string{}
	for _, value := range stringList(schema.Get("response_types")) {
		responseTypes = append(responseTypes, strings.Join(sortedStrings(unique(strings.Split(value, " "))), " "))
	}
	schema.Set("response_types", anyList(responseTypes))
	enumChecks := []struct {
		prop string
		only []string
	}{
		{"application_type", []string{"native", "web"}},
		{"default_acr_values", []string{}},
		{"grant_types", p.grantTypes},
		{"id_token_signed_response_alg", idTokenSigningAlgs},
		{"response_types", []string{"code"}},
		{"response_modes", responseModesHandled},
		{"subject_type", []string{"public"}},
		{"token_endpoint_auth_method", clientAuthMethods},
		{"token_endpoint_auth_signing_alg", tokenEndpointAuthSigningAlgs(method)},
	}
	for _, check := range enumChecks {
		value := schema.Get(check.prop)
		if isUndefined(value) {
			continue
		}
		if contains(arrayMetadata, check.prop) {
			valid := true
			for _, item := range stringList(value) {
				if !contains(check.only, item) {
					valid = false
				}
			}
			if !valid {
				if len(check.only) > 0 {
					return invalidate(check.prop + " can only contain " + formatList(check.only, true))
				}
				return invalidate(check.prop + " must be empty (no values are allowed)")
			}
		} else if text, _ := value.(string); !contains(check.only, text) {
			if len(check.only) > 0 {
				return invalidate(check.prop + " must be " + formatList(check.only, true))
			}
			return invalidate(check.prop + " must not be provided (no values are allowed)")
		}
	}
	for _, prop := range webURIMetadata {
		value := schema.Get(prop)
		if isUndefined(value) {
			continue
		}
		if contains(httpsURIMetadata, prop) {
			if !isHTTPSURI(value) {
				return invalidate(prop + " must be a https uri")
			}
		} else if !isWebURI(value) {
			return invalidate(prop + " must be a web uri")
		}
	}
	if scope := str(schema, "scope"); scope != "" {
		parsed := unique(strings.Split(scope, " "))
		for _, item := range parsed {
			if !contains(p.supportedScopes, item) {
				return invalidate("scope must only contain Authorization Server supported scope values")
			}
		}
		schema.Set("scope", strings.Join(parsed, " "))
	}
	grantTypes := stringList(schema.Get("grant_types"))
	if list := stringList(schema.Get("post_logout_redirect_uris")); schema.Has("post_logout_redirect_uris") && !isUndefined(schema.Get("post_logout_redirect_uris")) {
		if err := validateRedirectURIs(list, "post_logout_redirect_uris", str(schema, "application_type"), grantTypes); err != nil {
			return nil, err
		}
	}
	if err := validateRedirectURIs(stringList(schema.Get("redirect_uris")), "redirect_uris", str(schema, "application_type"), grantTypes); err != nil {
		return nil, err
	}
	for _, contact := range stringList(schema.Get("contacts")) {
		if !contactPattern.MatchString(contact) {
			return invalidate("contacts can only contain email addresses")
		}
	}
	if p.config.RequirePushedAuthorizationRequests {
		schema.Set("require_pushed_authorization_requests", true)
	}
	for _, prop := range []string{"default_max_age", "client_secret_expires_at"} {
		if value := schema.Get(prop); !isUndefined(value) {
			number, ok := value.(float64)
			if !isSafeInteger(value) || !ok || number < 0 {
				return invalidate(prop + " must be a non-negative integer")
			}
		}
	}
	responseTypeSet := map[string]bool{}
	for _, value := range responseTypes {
		for _, part := range strings.Split(value, " ") {
			responseTypeSet[part] = true
		}
	}
	if len(responseTypeSet) > 0 && len(stringList(schema.Get("redirect_uris"))) == 0 {
		return invalidate("redirect_uris must contain members")
	}
	if modes, ok := schema.Get("response_modes").([]any); ok && len(responseTypeSet) > 0 && len(modes) == 0 {
		return invalidate("response_modes must contain members")
	}
	if responseTypeSet["code"] && !contains(grantTypes, "authorization_code") {
		grantTypes = append(grantTypes, "authorization_code")
	}
	if contains(grantTypes, "authorization_code") && !responseTypeSet["code"] {
		filtered := []string{}
		removed := false
		for _, value := range grantTypes {
			if value == "authorization_code" && !removed {
				removed = true
				continue
			}
			filtered = append(filtered, value)
		}
		grantTypes = filtered
	}
	schema.Set("grant_types", anyList(grantTypes))
	if truthy(schema.Get("jwks")) || !isUndefined(schema.Get("jwks")) {
		if !isUndefined(schema.Get("jwks")) && !isUndefined(schema.Get("jwks_uri")) {
			return invalidate("jwks and jwks_uri must not be used at the same time")
		}
	}
	// ensureStripUnrecognized
	out := core.NewObject()
	schema.Entries(func(key string, value any) bool {
		if contains(recognizedMetadata, key) || contains(extraClientProperties, key) {
			out.SetRaw(key, value)
		}
		return true
	})
	if jwks := out.Get("jwks"); !isUndefined(jwks) {
		if _, err := checkClientJWKS(jwks); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func tokenEndpointAuthSigningAlgs(method string) []string {
	out := []string{}
	for _, alg := range clientAuthAlgs {
		switch method {
		case "private_key_jwt":
			if !strings.HasPrefix(alg, "HS") {
				out = append(out, alg)
			}
		case "client_secret_jwt":
			if strings.HasPrefix(alg, "HS") {
				out = append(out, alg)
			}
		}
	}
	return out
}

func clientNeedsSecret(metadata *core.Object) bool {
	if !contains(nonSecretMethods, str(metadata, "token_endpoint_auth_method")) {
		return true
	}
	for _, prop := range []string{"id_token_signed_response_alg", "token_endpoint_auth_signing_alg"} {
		if strings.HasPrefix(str(metadata, prop), "HS") {
			return true
		}
	}
	return false
}

func validateRedirectURIs(uris []string, label, applicationType string, grantTypes []string) error {
	for _, uri := range uris {
		parsed, err := parseURL(uri)
		if err != nil {
			return errInvalidClientMetadata(label + " must only contain valid uris")
		}
		if strings.Contains(parsed.Href, "#") || strings.Contains(uri, "#") {
			return errInvalidClientMetadata(label + " must not contain fragments")
		}
		switch applicationType {
		case "web":
			if parsed.Protocol != "https:" && parsed.Protocol != "http:" {
				return errInvalidClientMetadata(label + " must only contain web uris")
			}
			if contains(grantTypes, "implicit") {
				if parsed.Protocol == "http:" {
					return errInvalidClientMetadata(label + " for web clients using implicit flow MUST only register URLs using the https scheme")
				}
				if parsed.Hostname == "localhost" {
					return errInvalidClientMetadata(label + " for web clients using implicit flow must not be using localhost")
				}
			}
		case "native":
			switch parsed.Protocol {
			case "http:":
				if !contains(loopbacks, parsed.Hostname) {
					return errInvalidClientMetadata(label + " for native clients using http as a protocol can only use loopback addresses as hostnames")
				}
			case "https:":
				if contains(loopbacks, parsed.Hostname) {
					return errInvalidClientMetadata(label + " for native clients using claimed HTTPS URIs must not be using " + parsed.Hostname + " as hostname")
				}
			default:
				if contains(forbiddenSchemes, parsed.Protocol) {
					return errInvalidClientMetadata(label + " must not use the " + strings.TrimSuffix(parsed.Protocol, ":") + " URI scheme")
				}
			}
		}
	}
	return nil
}

// checkClientJWKS is validateJWKS + checkJWK: the usable public keys of a client JWKS.
func checkClientJWKS(value any) ([]*core.Object, error) {
	invalid := errInvalidClientMetadata("client JSON Web Key Set is invalid")
	jwks, ok := value.(*core.Object)
	if !ok || jwks == nil {
		return nil, invalid
	}
	list, ok := jwks.Get("keys").([]any)
	if !ok {
		return nil, invalid
	}
	keys := []*core.Object{}
	for _, item := range list {
		if key, ok := item.(*core.Object); !ok || key == nil {
			return nil, invalid
		}
	}
	for _, item := range list {
		jwk := item.(*core.Object)
		kty, ok := jwk.Get("kty").(string)
		if !ok || kty == "" {
			return nil, invalid
		}
		requiredString := func(name string) bool {
			text, ok := jwk.Get(name).(string)
			return ok && text != ""
		}
		var required, private []string
		switch kty {
		case "EC":
			if !requiredString("crv") {
				return nil, invalid
			}
			if !contains([]string{"P-256", "P-384", "P-521"}, str(jwk, "crv")) {
				continue
			}
			required, private = []string{"x", "y"}, []string{"d"}
		case "OKP":
			if !requiredString("crv") {
				return nil, invalid
			}
			if !contains([]string{"Ed25519", "X25519"}, str(jwk, "crv")) {
				continue
			}
			required, private = []string{"x"}, []string{"d"}
		case "AKP":
			required, private = []string{"alg", "pub"}, []string{"priv"}
		case "RSA":
			required, private = []string{"e", "n"}, []string{"d", "p", "q", "dp", "dq", "qi", "oth"}
		case "oct":
			return nil, invalid
		default:
			continue
		}
		for _, name := range required {
			if !requiredString(name) {
				return nil, invalid
			}
		}
		for _, name := range private {
			if !isUndefined(jwk.Get(name)) {
				return nil, invalid
			}
		}
		for _, name := range []string{"alg", "kid", "use"} {
			if !isUndefined(jwk.Get(name)) && !requiredString(name) {
				return nil, invalid
			}
		}
		if x5c := jwk.Get("x5c"); !isUndefined(x5c) {
			list, ok := x5c.([]any)
			if !ok {
				return nil, invalid
			}
			for _, cert := range list {
				if text, ok := cert.(string); !ok || text == "" {
					return nil, invalid
				}
			}
		}
		keys = append(keys, jwk)
	}
	return keys, nil
}

// oidcClient is a loaded client (oidc-provider's Client instance).
type oidcClient struct {
	p        *Provider
	metadata *core.Object
	id       string

	mu         sync.Mutex
	keys       []*core.Object
	freshUntil int64
}

func (c *oidcClient) clientID() string       { return c.id }
func (c *oidcClient) authMethod() string     { return str(c.metadata, "token_endpoint_auth_method") }
func (c *oidcClient) redirectURIs() []string { return stringList(c.metadata.Get("redirect_uris")) }
func (c *oidcClient) postLogoutRedirectURIs() []string {
	return stringList(c.metadata.Get("post_logout_redirect_uris"))
}
func (c *oidcClient) grantTypeAllowed(grant string) bool {
	return contains(stringList(c.metadata.Get("grant_types")), grant)
}
func (c *oidcClient) responseTypeAllowed(value string) bool {
	return contains(stringList(c.metadata.Get("response_types")), value)
}
func (c *oidcClient) scope() string   { return str(c.metadata, "scope") }
func (c *oidcClient) dpopBound() bool { return c.metadata.Get("dpop_bound_access_tokens") == true }
func (c *oidcClient) requirePAR() bool {
	return c.metadata.Get("require_pushed_authorization_requests") == true
}
func (c *oidcClient) applicationType() string      { return str(c.metadata, "application_type") }
func (c *oidcClient) backchannelLogoutURI() string { return str(c.metadata, "backchannel_logout_uri") }
func (c *oidcClient) clientName() string           { return str(c.metadata, "client_name") }
func (c *oidcClient) idTokenAlg() string           { return str(c.metadata, "id_token_signed_response_alg") }
func (c *oidcClient) includeSid() bool {
	return c.backchannelLogoutURI() != "" && c.metadata.Get("backchannel_logout_session_required") == true
}
func (c *oidcClient) requireAuthTime() bool { return c.metadata.Get("require_auth_time") == true }
func (c *oidcClient) defaultMaxAge() (float64, bool) {
	value, ok := c.metadata.Get("default_max_age").(float64)
	return value, ok
}
func (c *oidcClient) defaultAcrValues() []string {
	return stringList(c.metadata.Get("default_acr_values"))
}
func (c *oidcClient) lifetime(key string) (int64, bool) {
	value, ok := c.metadata.Get(key).(float64)
	if !ok || value <= 0 {
		return 0, false
	}
	return int64(value), true
}

// compareSecret is compareClientSecret (constantEquals with a 1000 ms floor in oidc-provider).
func (c *oidcClient) compareSecret(actual string) bool {
	return constantEquals(str(c.metadata, "client_secret"), actual)
}

func (c *oidcClient) redirectAllowed(value string, allowed []string) bool {
	if contains(allowed, value) {
		return true
	}
	if c.applicationType() != "native" {
		return false
	}
	without, ok := stripLoopbackPort(value)
	if !ok {
		return false
	}
	for _, candidate := range allowed {
		if other, ok := stripLoopbackPort(candidate); ok && other == without {
			return true
		}
	}
	return false
}

func (c *oidcClient) redirectURIAllowed(value string) bool {
	return c.redirectAllowed(value, c.redirectURIs())
}

func (c *oidcClient) postLogoutRedirectURIAllowed(value string) bool {
	return c.redirectAllowed(value, c.postLogoutRedirectURIs())
}

// stripLoopbackPort removes the port of a loopback http URI (native clients may use any port).
func stripLoopbackPort(uri string) (string, bool) {
	parsed, err := parseURL(uri)
	if err != nil || parsed.Protocol != "http:" || !contains(loopbacks, parsed.Hostname) {
		return "", false
	}
	schemeEnd := strings.Index(uri, "://")
	if schemeEnd == -1 {
		return "", false
	}
	authorityStart := schemeEnd + 3
	rest := uri[authorityStart:]
	authorityEnd := len(uri)
	if index := strings.IndexAny(rest, "/?#"); index >= 0 {
		authorityEnd = authorityStart + index
	}
	authority := uri[authorityStart:authorityEnd]
	hostStart := strings.LastIndex(authority, "@") + 1
	hostAndPort := authority[hostStart:]
	portStart := 0
	if strings.HasPrefix(hostAndPort, "[") {
		bracketEnd := strings.Index(hostAndPort, "]")
		if bracketEnd == -1 || bracketEnd+1 >= len(hostAndPort) || hostAndPort[bracketEnd+1] != ':' {
			return uri, true
		}
		portStart = hostStart + bracketEnd + 1
	} else {
		portOffset := strings.LastIndex(hostAndPort, ":")
		if portOffset == -1 {
			return uri, true
		}
		portStart = hostStart + portOffset
	}
	port := authority[portStart+1:]
	if strings.Trim(port, "0123456789") != "" {
		return "", false
	}
	return uri[:authorityStart+portStart] + uri[authorityEnd:], true
}

// currentKeys are the client's public keys as last loaded (inline jwks, or the cached jwks_uri document).
func (c *oidcClient) currentKeys() []*core.Object {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.keys
}

// fresh is ClientKeyStore.fresh: inline keys are always fresh; fetched keys until their cache expires.
func (c *oidcClient) fresh() bool {
	if str(c.metadata, "jwks_uri") == "" {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.freshUntil > epoch(c.p.now())
}

// refresh is ClientKeyStore.refresh: fetches jwks_uri unless the cached keys are fresh.
func (c *oidcClient) refresh(ctx context.Context) error {
	uri := str(c.metadata, "jwks_uri")
	if uri == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.freshUntil > epoch(c.p.now()) {
		return nil
	}
	failed := errInvalidClientMetadata("client JSON Web Key Set failed to be refreshed")
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return failed
	}
	request.Header.Set("accept", "application/json")
	response, err := c.p.outbound(request)
	if err != nil {
		return failed
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return failed
	}
	best := epoch(c.p.now()) + 60
	if value := response.Header.Get("expires"); value != "" {
		if parsed, err := http.ParseTime(value); err == nil && epoch(parsed.UnixMilli()) > best {
			best = epoch(parsed.UnixMilli())
		}
	}
	if match := maxAgePattern.FindStringSubmatch(response.Header.Get("cache-control")); match != nil {
		if maxAge, err := strconv.ParseInt(match[1], 10, 64); err == nil && epoch(c.p.now())+maxAge > best {
			best = epoch(c.p.now()) + maxAge
		}
	}
	c.freshUntil = best
	if response.StatusCode != 200 {
		return failed
	}
	parsed, err := core.ParseJSON(raw)
	if err != nil {
		return failed
	}
	keys, err := checkClientJWKS(parsed)
	if err != nil {
		return failed
	}
	c.keys = keys
	return nil
}

var maxAgePattern = regexp.MustCompile(`max-age=(\d+)`)

// outbound sends a provider request (client JWKS, back-channel logout) under the address rules.
func (p *Provider) outbound(request *http.Request) (*http.Response, error) {
	if p.config.HTTPClient != nil {
		return p.config.HTTPClient.Do(request)
	}
	guarded := auth.CreateGuardedFetch(auth.GuardedFetchOptions{SafeFetchAddressOptions: auth.SafeFetchAddressOptions{
		AnyPort: true, AllowInsecureLocalhost: p.config.AllowInsecureLocalhost}})
	return guarded.Do(request)
}

// clientCache is the dynamicClients LRU: loaded clients by their properties' hash.
type clientCache struct {
	mu      sync.Mutex
	clients map[string]*oidcClient
	order   []string
}

func newClientCache() *clientCache { return &clientCache{clients: map[string]*oidcClient{}} }

// findClient is Client.find: nil when the client is missing, revoked or unusable. Invalid stored metadata fails.
func (p *Provider) findClient(ctx context.Context, id string) (*oidcClient, error) {
	if id == "" {
		return nil, nil
	}
	properties, err := p.adapter.Model("Client").Find(ctx, id)
	if err != nil || properties == nil {
		return nil, err
	}
	digest := sha256.Sum256(utf8Bytes(stringify(properties)))
	key := b64url(digest[:])
	p.clientCache.mu.Lock()
	cached := p.clientCache.clients[key]
	p.clientCache.mu.Unlock()
	if cached != nil {
		return cached, nil
	}
	metadata, err := p.clientSchema(ctx, properties)
	if err != nil {
		return nil, err
	}
	client := &oidcClient{p: p, metadata: metadata, id: str(metadata, "client_id")}
	if jwks := metadata.Get("jwks"); !isUndefined(jwks) {
		if client.keys, err = checkClientJWKS(jwks); err != nil {
			return nil, err
		}
	}
	p.clientCache.mu.Lock()
	if len(p.clientCache.order) >= 100 {
		oldest := p.clientCache.order[0]
		p.clientCache.order = p.clientCache.order[1:]
		delete(p.clientCache.clients, oldest)
	}
	p.clientCache.clients[key] = client
	p.clientCache.order = append(p.clientCache.order, key)
	p.clientCache.mu.Unlock()
	return client, nil
}

// backchannelLogout signs a logout token for the account and POSTs it to the client.
func (p *Provider) backchannelLogout(ctx context.Context, client *oidcClient, sub, sid string) error {
	payload := core.NewObject("sub", sub, "events", core.NewObject("http://schemas.openid.net/event/backchannel-logout", core.NewObject()),
		"jti", nanoid(43))
	if client.metadata.Get("backchannel_logout_session_required") == true {
		payload.Set("sid", sid)
	}
	now := epoch(p.now())
	payload.Set("aud", client.clientID())
	payload.Set("exp", now+120)
	payload.Set("iat", now)
	payload.Set("iss", p.issuer)
	token, err := p.keys.sign(payload, client.idTokenAlg(), "logout+jwt")
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.backchannelLogoutURI(),
		strings.NewReader(formEncode([][2]string{{"logout_token", token}})))
	if err != nil {
		return err
	}
	request.Header.Set("content-type", "application/x-www-form-urlencoded")
	response, err := p.outbound(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != 200 && response.StatusCode != 204 {
		return errors.New("expected 200 OK from " + client.backchannelLogoutURI() + ", got: " + strconv.Itoa(response.StatusCode))
	}
	return nil
}

// constantEquals is a constant-time string comparison.
func constantEquals(a, b string) bool {
	if len(a) != len(b) {
		subtle.ConstantTimeCompare([]byte(a), []byte(a))
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
