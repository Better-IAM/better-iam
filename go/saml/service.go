package saml

// Port of packages/saml/src/index.ts: tenant-specific SAML service-provider connections (configured or managed per
// tenant at runtime), SP-initiated and opt-in IdP-initiated sign-in with persistent replay checks, signed metadata,
// account linking, and the HTTP routes mounted with iam.UseProtocol.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const (
	protocolNamespace  = "urn:oasis:names:tc:SAML:2.0:protocol"
	assertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion"
	// redirectHeader asks the host to answer with a 303 to this URL instead (iam.UseProtocol does, adding the session
	// cookie when the JSON body issued a session, and stripping the header).
	redirectHeader = "x-better-iam-redirect"
)

// SamlConnection is a connection fixed in deployment configuration (or built from a tenant-managed record).
type SamlConnection struct {
	ID string `json:"id"`
	// ProviderID is the provider key accounts linked through this connection are stored under ("" = ID).
	ProviderID      string   `json:"providerId,omitempty"`
	TenantID        string   `json:"tenantId"`
	EntryPoint      string   `json:"entryPoint"`
	IdpIssuer       string   `json:"idpIssuer"`
	IdpCertificates []string `json:"idpCertificates"`
	EntityID        string   `json:"entityId"`
	CallbackURL     string   `json:"callbackUrl"`
	PrivateKey      string   `json:"privateKey"`
	// PublicCertificate is the SP signing certificate published in metadata.
	PublicCertificate          string `json:"publicCertificate"`
	DecryptionPrivateKey       string `json:"decryptionPrivateKey,omitempty"`
	DecryptionCertificate      string `json:"decryptionCertificate,omitempty"`
	RequireEncryptedAssertions bool   `json:"requireEncryptedAssertions,omitempty"`
	// TrustedEmailDomains are the domains whose email attributes this IdP is trusted to verify.
	TrustedEmailDomains []string `json:"trustedEmailDomains,omitempty"`
	// AllowIdpInitiated accepts IdP-initiated (unsolicited) sign-in at the callback URL; each assertion once.
	AllowIdpInitiated bool `json:"allowIdpInitiated,omitempty"`
	// TrustScimProvisioned links a first sign-in to the account a SCIM connection of the tenant provisioned for the
	// same verified email: true (every SCIM connection), a list of SCIM connection IDs ([]string or []any), or nil.
	TrustScimProvisioned any `json:"trustScimProvisioned,omitempty"`
	// MapAttributes maps the validated assertion attributes (the Node-SAML profile) to identity attributes; nil
	// leaves them untouched.
	MapAttributes func(profile *core.Object) *core.Object `json:"-"`
}

// SamlServiceProvider is the deployment's own SAML service-provider identity, shared by every tenant-managed
// connection.
type SamlServiceProvider struct {
	// BaseURL is the public HTTPS origin (and optional path prefix) the SAML routes are served from.
	BaseURL           string `json:"baseUrl"`
	PrivateKey        string `json:"privateKey"`
	PublicCertificate string `json:"publicCertificate"`
	// DecryptionPrivateKey and DecryptionCertificate are needed for connections that require encrypted assertions.
	DecryptionPrivateKey  string `json:"decryptionPrivateKey,omitempty"`
	DecryptionCertificate string `json:"decryptionCertificate,omitempty"`
}

// Principal is an authenticated principal as the host's authenticate callback returns it.
type Principal struct {
	Identity *core.Object
	Session  *core.Object
}

// SamlConfigOptions configure CreateSamlService.
type SamlConfigOptions struct {
	Store core.IamStore
	// Connections are fixed in deployment configuration; tenant-managed connections live in the database.
	Connections []SamlConnection
	// ServiceProvider enables tenant-managed connections (CreateConnection and friends).
	ServiceProvider *SamlServiceProvider
	// Authorize authorizes connection management (`iam:saml:connections:*` on `saml/{id}`).
	Authorize func(ctx context.Context, credential core.CredentialInput, action string, resource core.ResourceRef) error
	// BasePath is where the routes are served ("" = "/saml").
	BasePath               string
	CompleteAuthentication func(ctx context.Context, input *core.Object) (any, error)
	Authenticate           func(ctx context.Context, credential core.CredentialInput) (*Principal, error)
	// AssertTrustChange runs before a tenant-managed connection starts trusting something new.
	AssertTrustChange func(ctx context.Context, credential core.CredentialInput, tenantID, providerID string) error
	// TrustedOrigins (nil = none given).
	TrustedOrigins []string
	// AfterSignIn is where the ACS sends the browser after a sign-in (nil = answer JSON only).
	AfterSignIn *string
	// MfaURL is where to send the browser when the person still has to pass MFA (with AfterSignIn).
	MfaURL *string
	// ErrorURL is where to send the browser when a sign-in fails, with `?error=CODE` (with AfterSignIn).
	ErrorURL *string
	// RevokeSession revokes the local IAM session.
	RevokeSession func(ctx context.Context, credential core.CredentialInput) (any, error)
	// Now is Date.now() (Go-only; default the system clock).
	Now func() int64
}

// SamlService is the service CreateSamlService returns.
type SamlService struct {
	config        SamlConfigOptions
	basePath      string
	connections   map[string]*SamlConnection
	order         []string
	sp            *SamlServiceProvider
	spBase        string
	afterSignIn   *string
	mfaURL        *string
	errorURL      *string
	now           func() int64
	redirectBases map[string]bool
}

// BeginResult is what Begin returns: the IdP URL, the RelayState and the browser binding.
type BeginResult struct {
	URL        string `json:"url"`
	RelayState string `json:"relayState"`
	Binding    string `json:"binding"`
}

// CallbackInput is a posted SAML response with its RelayState and browser binding.
type CallbackInput struct {
	SamlResponse string
	RelayState   string
	Binding      string
}

func hashHex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// connectionName is the shape of tenant-managed connection IDs (they appear in SAML URLs).
var connectionName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)
var domainName = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$`)
var attributeName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,63}$`)
var errorCode = regexp.MustCompile(`^[A-Z_]{2,64}$`)
var emailShape = regexp.MustCompile(`^[^\s\x0b\x{a0}\x{feff}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}@]+@[^\s\x0b\x{a0}\x{feff}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}@]+$`)

func samlInvalid(message string) error { return core.NewIamError("SAML_INVALID", message, 401) }

func configuration(message string) error { return core.NewIamError("configuration", message) }

// --- the replay cache ---------------------------------------------------------------------------------------------

// SamlCache is createSamlCache: the shared request cache, scoped to a tenant and connection. Run response
// verification inside one store transaction.
type SamlCache struct {
	store             core.IamStore
	tenantID          string
	connectionID      string
	expectedRequestID string
	// Now is Date.now().
	Now func() int64
}

// CreateSamlCache is createSamlCache(store, tenantId, connectionId, expectedRequestId) ("" = no expected ID).
func CreateSamlCache(store core.IamStore, tenantID, connectionID, expectedRequestID string) *SamlCache {
	return &SamlCache{store: store, tenantID: tenantID, connectionID: connectionID, expectedRequestID: expectedRequestID,
		Now: func() int64 { return time.Now().UnixMilli() }}
}

func (c *SamlCache) id(key string) string {
	return hashHex(c.tenantID + ":" + c.connectionID + ":" + key)
}

// SaveAsync stores a request ID for ten minutes.
func (c *SamlCache) SaveAsync(ctx context.Context, key, value string) error {
	createdAt := float64(c.Now())
	return c.store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		_, err := tx.Insert(ctx, "samlRequests", core.NewObject("id", c.id(key), "tenantId", c.tenantID, "value", value,
			"createdAt", createdAt, "expiresAt", createdAt+600_000))
		return err
	})
}

// GetAsync reads a live request ID.
func (c *SamlCache) GetAsync(ctx context.Context, key string) (string, bool, error) {
	if c.expectedRequestID != "" && key != c.expectedRequestID {
		return "", false, nil
	}
	item, err := c.store.Get(ctx, "samlRequests", c.id(key))
	if err != nil || item == nil {
		return "", false, err
	}
	expiresAt, _ := item.Number("expiresAt")
	if item.Get("tenantId") != c.tenantID || !(expiresAt > float64(c.Now())) {
		return "", false, nil
	}
	value, ok := item.Get("value").(string)
	return value, ok && value != "", nil
}

// RemoveAsync consumes a request ID.
func (c *SamlCache) RemoveAsync(ctx context.Context, key string) (string, bool, error) {
	if key == "" || (c.expectedRequestID != "" && key != c.expectedRequestID) {
		return "", false, nil
	}
	var value string
	var found bool
	err := c.store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		item, err := tx.Get(ctx, "samlRequests", c.id(key))
		if err != nil || item == nil || item.Get("tenantId") != c.tenantID {
			return err
		}
		if err := tx.Delete(ctx, "samlRequests", jsString(item.Get("id"))); err != nil {
			return err
		}
		value, _ = item.Get("value").(string)
		found = true
		return nil
	})
	return value, found, err
}

func activeTenant(ctx context.Context, store core.IamStore, tenantID string) error {
	active, err := core.TenantTreeActive(ctx, store, tenantID)
	if err != nil {
		return err
	}
	if !active {
		return core.NewIamError("TENANT_INACTIVE", "Tenant unavailable.", 403)
	}
	return nil
}

// ValidateSamlEnvelope supplements the cryptographic checks with exact response destination checks. A nil
// expectedRequestID validates an IdP-initiated response, which must not answer any request.
func ValidateSamlEnvelope(xml, callbackURL string, expectedRequestID *string, encryptedRequired bool) error {
	if core.UTF16Len(xml) > 1024*1024 || unsafeXML.MatchString(xml) {
		return samlInvalid("Unsafe SAML document.")
	}
	if xml == "" {
		return errors.New("Cannot read properties of undefined (reading 'documentElement')")
	}
	doc, err := ParseXML(xml)
	var root *Node
	if err == nil {
		root = doc.DocumentElement()
	}
	invalid := err != nil || root == nil || root.NamespaceURI != protocolNamespace || root.Local != "Response" ||
		root.Attribute("Destination") != callbackURL
	if !invalid {
		if expectedRequestID == nil {
			invalid = root.HasAttribute("InResponseTo")
		} else {
			invalid = root.Attribute("InResponseTo") != *expectedRequestID
		}
	}
	if invalid {
		return samlInvalid("SAML response binding is invalid.")
	}
	// Judged where Node-SAML reads assertions: the Response's own children.
	children := func(name string) int {
		return len(root.ChildElements(func(n *Node) bool { return n.NamespaceURI == assertionNamespace && n.Local == name }))
	}
	if encryptedRequired && (children("EncryptedAssertion") != 1 || children("Assertion") != 0) {
		return samlInvalid("An encrypted assertion is required.")
	}
	for _, subject := range root.ElementsByTagNameNS(assertionNamespace, "SubjectConfirmationData") {
		if subject.Attribute("Recipient") != callbackURL {
			return samlInvalid("SAML subject recipient is invalid.")
		}
		if expectedRequestID == nil && subject.HasAttribute("InResponseTo") {
			return samlInvalid("An unsolicited response cannot answer a request.")
		}
	}
	return nil
}

// returnPath is a same-site path to return to after sign-in: an absolute path, never scheme-relative, without
// control characters.
func returnPath(value any) (string, error) {
	text, ok := value.(string)
	if !ok || core.UTF16Len(text) > 1024 || !strings.HasPrefix(text, "/") || strings.HasPrefix(text, "//") ||
		strings.ContainsFunc(text, func(r rune) bool { return r <= 0x1f || r == 0x7f || r == '\\' }) {
		return "", core.NewIamError("INVALID_INPUT", "returnTo must be a path on this site, such as /dashboard.")
	}
	return text, nil
}

// scimTrust validates trustScimProvisioned: a boolean, or up to 20 distinct SCIM connection IDs (deduplicated).
func scimTrust(value any, code string) (any, error) {
	if value == nil || core.IsUndefined(value) {
		return false, nil
	}
	if flag, ok := value.(bool); ok {
		return flag, nil
	}
	var list []any
	switch v := value.(type) {
	case []any:
		list = v
	case []string:
		for _, item := range v {
			list = append(list, item)
		}
	default:
		return nil, core.NewIamError(code, "trustScimProvisioned is a boolean or a list of SCIM connection IDs.")
	}
	if len(list) > 20 {
		return nil, core.NewIamError(code, "trustScimProvisioned is a boolean or a list of SCIM connection IDs.")
	}
	for _, item := range list {
		id, ok := item.(string)
		if !ok || id == "" || core.UTF16Len(id) > 128 {
			return nil, core.NewIamError(code, "trustScimProvisioned is a boolean or a list of SCIM connection IDs.")
		}
	}
	if len(list) == 0 {
		return false, nil
	}
	var unique []any
	seen := map[string]bool{}
	for _, item := range list {
		id := item.(string)
		if !seen[id] {
			seen[id] = true
			unique = append(unique, id)
		}
	}
	return unique, nil
}

// parseURL is `new URL(value)`.
func parseURL(value string) (*auth.FetchURL, error) { return auth.ParseFetchURL(value) }

func urlOrigin(u *auth.FetchURL) string {
	switch u.Protocol {
	case "http:", "https:", "ws:", "wss:", "ftp:":
		return u.Protocol + "//" + u.Host
	}
	return "null"
}

func hasCredentials(u *auth.FetchURL) bool {
	if u.User == nil {
		return false
	}
	password, _ := u.User.Password()
	return u.User.Username() != "" || password != ""
}

// CreateSamlService is createSamlService(config).
func CreateSamlService(config SamlConfigOptions) (*SamlService, error) {
	s := &SamlService{config: config, connections: map[string]*SamlConnection{}, sp: config.ServiceProvider}
	s.now = config.Now
	if s.now == nil {
		s.now = func() int64 { return time.Now().UnixMilli() }
	}
	s.basePath = config.BasePath
	if s.basePath == "" {
		s.basePath = "/saml"
	}
	s.basePath = strings.TrimSuffix(s.basePath, "/")
	for index := range config.Connections {
		item := config.Connections[index]
		if item.ID == "" || s.connections[item.ID] != nil || item.TenantID == "" || item.IdpIssuer == "" || item.EntityID == "" ||
			item.PrivateKey == "" || item.PublicCertificate == "" || len(item.IdpCertificates) == 0 {
			return nil, configuration("SAML connection configuration is incomplete.")
		}
		for _, value := range []string{item.EntryPoint, item.CallbackURL} {
			parsed, err := parseURL(value)
			if err != nil {
				return nil, errors.New("Invalid URL")
			}
			if parsed.Protocol != "https:" || hasCredentials(parsed) || parsed.Fragment != "" {
				return nil, configuration("SAML endpoints require HTTPS.")
			}
		}
		if item.RequireEncryptedAssertions && (item.DecryptionPrivateKey == "" || item.DecryptionCertificate == "") {
			return nil, configuration("Encrypted SAML assertions require decryption key and certificate.")
		}
		for _, id := range s.order {
			if s.connections[id].CallbackURL == item.CallbackURL {
				return nil, configuration("SAML callback URLs must be unique per connection.")
			}
		}
		for _, domain := range item.TrustedEmailDomains {
			if !domainName.MatchString(domain) {
				return nil, configuration("Trusted SAML email domains must be exact domain names.")
			}
		}
		if _, err := scimTrust(item.TrustScimProvisioned, "configuration"); err != nil {
			return nil, err
		}
		item.IdpCertificates = append([]string(nil), item.IdpCertificates...)
		s.connections[item.ID] = &item
		s.order = append(s.order, item.ID)
	}
	if sp := s.sp; sp != nil {
		parsed, err := parseURL(sp.BaseURL)
		if err != nil {
			return nil, errors.New("Invalid URL")
		}
		if parsed.Protocol != "https:" || hasCredentials(parsed) || parsed.Fragment != "" || parsed.RawQuery != "" ||
			sp.PrivateKey == "" || sp.PublicCertificate == "" {
			return nil, configuration("The SAML service provider needs an HTTPS base URL, a private key, and a certificate.")
		}
		s.spBase = urlOrigin(parsed) + strings.TrimSuffix(parsed.EscapedPath(), "/")
	}
	// Redirect targets: a path on this site, or a URL on an origin this service already trusts.
	s.redirectBases = map[string]bool{}
	for _, origin := range config.TrustedOrigins {
		s.redirectBases[origin] = true
	}
	if s.spBase != "" {
		if parsed, err := parseURL(s.spBase); err == nil {
			s.redirectBases[urlOrigin(parsed)] = true
		}
	}
	for _, id := range s.order {
		if parsed, err := parseURL(s.connections[id].CallbackURL); err == nil {
			s.redirectBases[urlOrigin(parsed)] = true
		}
	}
	var err error
	if s.afterSignIn, err = s.redirectTarget(config.AfterSignIn, "afterSignIn"); err != nil {
		return nil, err
	}
	if s.mfaURL, err = s.redirectTarget(config.MfaURL, "mfaUrl"); err != nil {
		return nil, err
	}
	if s.errorURL, err = s.redirectTarget(config.ErrorURL, "errorUrl"); err != nil {
		return nil, err
	}
	if (s.mfaURL != nil && *s.mfaURL != "" || s.errorURL != nil && *s.errorURL != "") && (s.afterSignIn == nil || *s.afterSignIn == "") {
		return nil, configuration("SAML mfaUrl and errorUrl need afterSignIn.")
	}
	return s, nil
}

func (s *SamlService) redirectTarget(value *string, name string) (*string, error) {
	if value == nil {
		return nil, nil
	}
	invalid := configuration("SAML " + name + " must be a path or a trusted HTTPS URL.")
	if strings.HasPrefix(*value, "/") {
		path, err := returnPath(*value)
		if err != nil {
			return nil, invalid
		}
		return &path, nil
	}
	parsed, err := parseURL(*value)
	if err != nil {
		return nil, invalid
	}
	if hasCredentials(parsed) || !s.redirectBases[urlOrigin(parsed)] {
		return nil, invalid
	}
	href := parsed.Href
	return &href, nil
}

// BasePath is the path the routes are served under.
func (s *SamlService) BasePath() string { return s.basePath }

type managedURLs struct{ entityID, acsURL, metadataURL, loginURL string }

func (s *SamlService) managedUrls(id string) managedURLs {
	root := s.spBase + s.basePath + "/" + encodeURIComponent(id)
	return managedURLs{root + "/metadata", root + "/acs", root + "/metadata", root + "/login"}
}

func recordStrings(record *core.Object, key string) []string {
	list, _ := record.Get(key).([]any)
	values := make([]string, 0, len(list))
	for _, item := range list {
		if text, ok := item.(string); ok {
			values = append(values, text)
		}
	}
	return values
}

func str(record *core.Object, key string) string {
	text, _ := record.Get(key).(string)
	return text
}

func (s *SamlService) fromRecord(record *core.Object) *SamlConnection {
	urls := s.managedUrls(str(record, "id"))
	mapping, _ := record.Get("attributeMapping").(*core.Object)
	connection := &SamlConnection{
		ID:                         str(record, "id"),
		ProviderID:                 str(record, "providerKey"),
		TenantID:                   str(record, "tenantId"),
		EntryPoint:                 str(record, "entryPoint"),
		IdpIssuer:                  str(record, "idpIssuer"),
		IdpCertificates:            recordStrings(record, "idpCertificates"),
		EntityID:                   urls.entityID,
		CallbackURL:                urls.acsURL,
		PrivateKey:                 s.sp.PrivateKey,
		PublicCertificate:          s.sp.PublicCertificate,
		DecryptionPrivateKey:       s.sp.DecryptionPrivateKey,
		DecryptionCertificate:      s.sp.DecryptionCertificate,
		RequireEncryptedAssertions: truthy(record.Get("requireEncryptedAssertions")),
		AllowIdpInitiated:          record.Get("allowIdpInitiated") == true,
		TrustScimProvisioned:       orFalse(record.Get("trustScimProvisioned")),
		TrustedEmailDomains:        recordStrings(record, "trustedEmailDomains"),
	}
	if mapping != nil && mapping.Len() > 0 {
		keys := mapping.Keys()
		connection.MapAttributes = func(profile *core.Object) *core.Object {
			attributes := core.NewObject()
			for _, attribute := range keys {
				name, _ := mapping.Get(attribute).(string)
				raw := profile.Get(name)
				value := raw
				if list, ok := raw.([]any); ok {
					value = first(list)
				}
				if text, ok := value.(string); ok {
					attributes.Set(attribute, text)
				}
			}
			return attributes
		}
	}
	return connection
}

func orFalse(value any) any {
	if value == nil || core.IsUndefined(value) {
		return false
	}
	return value
}

func (s *SamlService) staticConnection(id string) (*SamlConnection, error) {
	if item := s.connections[id]; item != nil {
		return item, nil
	}
	return nil, core.NewIamError("NOT_FOUND", "SAML connection unavailable.", 404)
}

// connection is a configured connection, or an enabled tenant-managed one.
func (s *SamlService) connection(ctx context.Context, id string, store core.IamStore) (*SamlConnection, error) {
	if store == nil {
		store = s.config.Store
	}
	if item := s.connections[id]; item != nil {
		return item, nil
	}
	if s.sp != nil && connectionName.MatchString(id) {
		record, err := store.Get(ctx, "samlConnections", id)
		if err != nil {
			return nil, err
		}
		if record != nil && truthy(record.Get("enabled")) {
			return s.fromRecord(record), nil
		}
	}
	return nil, core.NewIamError("NOT_FOUND", "SAML connection unavailable.", 404)
}

func (s *SamlService) summary(record *core.Object) (*core.Object, error) {
	urls := s.managedUrls(str(record, "id"))
	var certificates []any
	for _, certificate := range recordStrings(record, "idpCertificates") {
		info, err := CertificateDetails(certificate, s.now())
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, info.object())
	}
	if certificates == nil {
		certificates = []any{}
	}
	mapping := core.NewObject()
	if source, ok := record.Get("attributeMapping").(*core.Object); ok {
		mapping = source.Clone()
	}
	providerID := record.Get("providerKey")
	if providerID == nil || core.IsUndefined(providerID) {
		providerID = record.Get("id")
	}
	domains := []any{}
	for _, domain := range recordStrings(record, "trustedEmailDomains") {
		domains = append(domains, domain)
	}
	return core.NewObject(
		"id", record.Get("id"),
		"tenantId", record.Get("tenantId"),
		"name", record.Get("name"),
		"enabled", record.Get("enabled"),
		"entryPoint", record.Get("entryPoint"),
		"idpIssuer", record.Get("idpIssuer"),
		"certificates", certificates,
		"trustedEmailDomains", domains,
		"requireEncryptedAssertions", record.Get("requireEncryptedAssertions"),
		"attributeMapping", mapping,
		"allowIdpInitiated", record.Get("allowIdpInitiated") == true,
		"trustScimProvisioned", orFalse(record.Get("trustScimProvisioned")),
		"providerId", providerID,
		"entityId", urls.entityID,
		"acsUrl", urls.acsURL,
		"metadataUrl", urls.metadataURL,
		"loginUrl", urls.loginURL,
		"createdAt", record.Get("createdAt"),
		"updatedAt", record.Get("updatedAt"),
	), nil
}

// nullish is `value ?? fallback` for the members of an input or record.
func nullish(values ...any) any {
	for _, value := range values {
		if value != nil && !core.IsUndefined(value) {
			return value
		}
	}
	return core.Undefined
}

func get(object *core.Object, key string) any {
	if object == nil {
		return core.Undefined
	}
	return object.Get(key)
}

// settings validates administrator input, filling IdP details from metadata and unchanged values from current.
func (s *SamlService) settings(input *core.Object, current *core.Object) (*core.Object, error) {
	var imported *IdpMetadata
	if metadataXML := get(input, "metadataXml"); !core.IsUndefined(metadataXML) {
		parsed, err := ParseIdpMetadata(metadataXML)
		if err != nil {
			return nil, err
		}
		imported = parsed
	}
	var importedEntry, importedIssuer, importedCertificates any = core.Undefined, core.Undefined, core.Undefined
	if imported != nil {
		importedEntry, importedIssuer = imported.EntryPoint, imported.EntityID
		list := make([]any, len(imported.Certificates))
		for i, certificate := range imported.Certificates {
			list[i] = certificate
		}
		importedCertificates = list
	}
	name := nullish(get(input, "name"), get(current, "name"))
	entryPoint := nullish(get(input, "entryPoint"), importedEntry, get(current, "entryPoint"))
	idpIssuer := nullish(get(input, "idpIssuer"), importedIssuer, get(current, "idpIssuer"))
	certificates := nullish(get(input, "idpCertificates"), importedCertificates, get(current, "idpCertificates"))
	domains := nullish(get(input, "trustedEmailDomains"), get(current, "trustedEmailDomains"), []any{})
	mapping := nullish(get(input, "attributeMapping"), get(current, "attributeMapping"), core.NewObject())
	requireEncrypted := nullish(get(input, "requireEncryptedAssertions"), get(current, "requireEncryptedAssertions"), false)
	enabled := nullish(get(input, "enabled"), get(current, "enabled"), true)
	allowIdpInitiated := nullish(get(input, "allowIdpInitiated"), get(current, "allowIdpInitiated"), false)
	trustScim, err := scimTrust(nullish(get(input, "trustScimProvisioned"), get(current, "trustScimProvisioned"), false), "INVALID_INPUT")
	if err != nil {
		return nil, err
	}
	nameText, ok := name.(string)
	if !ok || core.JSTrim(nameText) == "" || core.UTF16Len(nameText) > 200 {
		return nil, core.NewIamError("INVALID_INPUT", "A connection name of at most 200 characters is required.")
	}
	entry, err := parseURL(jsString(entryPoint))
	if err != nil || entry.Protocol != "https:" || hasCredentials(entry) || entry.Fragment != "" {
		return nil, core.NewIamError("INVALID_INPUT", "The IdP sign-on URL must be an absolute HTTPS URL.")
	}
	issuerText, ok := idpIssuer.(string)
	if !ok || issuerText == "" || core.UTF16Len(issuerText) > 1024 {
		return nil, core.NewIamError("INVALID_INPUT", "The IdP issuer (entity ID) is required.")
	}
	certificateList, ok := certificates.([]any)
	if !ok || len(certificateList) == 0 || len(certificateList) > 5 {
		return nil, core.NewIamError("INVALID_INPUT", "Between one and five IdP signing certificates are required.")
	}
	domainList, ok := domains.([]any)
	if ok && len(domainList) <= 20 {
		for _, domain := range domainList {
			if text, isText := domain.(string); !isText || !domainName.MatchString(text) {
				ok = false
				break
			}
		}
	}
	if !ok || len(domainList) > 20 {
		return nil, core.NewIamError("INVALID_INPUT", "Trusted email domains must be exact domain names.")
	}
	mappingObject, ok := mapping.(*core.Object)
	if ok && mappingObject != nil && mappingObject.Len() <= 32 {
		for _, key := range mappingObject.Keys() {
			source, isText := mappingObject.Get(key).(string)
			if !attributeName.MatchString(key) || !isText || source == "" || core.UTF16Len(source) > 256 {
				ok = false
				break
			}
		}
	}
	if !ok || mappingObject == nil || mappingObject.Len() > 32 {
		return nil, core.NewIamError("INVALID_INPUT", "attributeMapping maps up to 32 identity attribute names to SAML attribute names.")
	}
	requireFlag, okRequire := requireEncrypted.(bool)
	enabledFlag, okEnabled := enabled.(bool)
	allowFlag, okAllow := allowIdpInitiated.(bool)
	if !okRequire || !okEnabled || !okAllow {
		return nil, core.NewIamError("INVALID_INPUT", "Invalid SAML connection settings.")
	}
	if requireFlag && (s.sp == nil || s.sp.DecryptionPrivateKey == "" || s.sp.DecryptionCertificate == "") {
		return nil, core.NewIamError("INVALID_INPUT", "Encrypted assertions need a service-provider decryption key.")
	}
	normalized := []any{}
	for _, certificate := range certificateList {
		text, err := NormalizeCertificate(certificate)
		if err != nil {
			return nil, err
		}
		if !containsAny(normalized, text) {
			normalized = append(normalized, text)
		}
	}
	lowered := []any{}
	for _, domain := range domainList {
		text := strings.ToLower(domain.(string))
		if !containsAny(lowered, text) {
			lowered = append(lowered, text)
		}
	}
	return core.NewObject(
		"name", core.JSTrim(nameText),
		"entryPoint", entry.Href,
		"idpIssuer", issuerText,
		"idpCertificates", normalized,
		"trustedEmailDomains", lowered,
		"attributeMapping", mappingObject.Clone(),
		"requireEncryptedAssertions", requireFlag,
		"allowIdpInitiated", allowFlag,
		"trustScimProvisioned", trustScim,
		"enabled", enabledFlag,
	), nil
}

func containsAny(list []any, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func anyStrings(value any) []string {
	list, _ := value.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

// trustWidened reports whether new settings make a connection trust more than before: another IdP issuer, an added
// signing certificate, unsolicited sign-in, more trusted email domains, or SCIM-provisioned accounts it did not link
// before.
func trustWidened(current, next *core.Object) bool {
	before := orFalse(current.Get("trustScimProvisioned"))
	after := orFalse(next.Get("trustScimProvisioned"))
	scimWidened := false
	if after == true {
		scimWidened = before != true
	} else if list, ok := after.([]any); ok && before != true {
		previous, _ := before.([]any)
		for _, id := range list {
			found := false
			for _, old := range previous {
				if old == id {
					found = true
				}
			}
			if !found {
				scimWidened = true
			}
		}
	}
	certificatesAdded := false
	currentCertificates := anyStrings(current.Get("idpCertificates"))
	for _, certificate := range anyStrings(next.Get("idpCertificates")) {
		if !contains(currentCertificates, certificate) {
			certificatesAdded = true
		}
	}
	domainsAdded := false
	currentDomains := anyStrings(current.Get("trustedEmailDomains"))
	for _, domain := range anyStrings(next.Get("trustedEmailDomains")) {
		if !contains(currentDomains, domain) {
			domainsAdded = true
		}
	}
	return scimWidened || next.Get("idpIssuer") != current.Get("idpIssuer") || certificatesAdded ||
		(next.Get("allowIdpInitiated") == true && current.Get("allowIdpInitiated") != true) || domainsAdded
}

// manager authorizes a management call on `saml/{id}` and returns the acting principal.
func (s *SamlService) manager(ctx context.Context, credential core.CredentialInput, action, tenantID, id string) (*Principal, error) {
	if s.sp == nil || s.config.Authorize == nil || s.config.Authenticate == nil {
		return nil, configuration("Managed SAML connections need serviceProvider, authorize, and authenticate.")
	}
	if err := s.config.Authorize(ctx, credential, action, core.ResourceRef{TenantID: tenantID, Type: "saml", ID: id}); err != nil {
		return nil, err
	}
	return s.config.Authenticate(ctx, credential)
}

func (s *SamlService) managed(ctx context.Context, tx core.IamStore, tenantID, id string) (*core.Object, error) {
	var record *core.Object
	if connectionName.MatchString(id) {
		found, err := tx.Get(ctx, "samlConnections", id)
		if err != nil {
			return nil, err
		}
		record = found
	}
	if record == nil || record.Get("tenantId") != tenantID {
		return nil, core.NewIamError("NOT_FOUND", "SAML connection not found.", 404)
	}
	return record, nil
}

func (s *SamlService) audit(ctx context.Context, tx core.IamStore, principal *Principal, tenantID, action, resourceID string) error {
	var actor any = core.Undefined
	if principal != nil && principal.Identity != nil {
		actor = principal.Identity.Get("id")
	}
	_, err := core.AppendAuditEvent(ctx, tx, core.NewObject("id", randomUUID(), "tenantId", tenantID, "actorId", actor,
		"action", action, "resourceId", resourceID, "timestamp", float64(s.now()), "outcome", "allow"))
	return err
}

func (s *SamlService) newSaml(item *SamlConnection, store core.IamStore, requestID, expectedRequestID string, unsolicited bool) *nodeSaml {
	cache := CreateSamlCache(store, item.TenantID, item.ID, expectedRequestID)
	cache.Now = s.now
	generate := func() string { return "_" + randomUUID() }
	if requestID != "" {
		generate = func() string { return requestID }
	}
	return &nodeSaml{options: samlOptions{
		entryPoint:       item.EntryPoint,
		issuer:           item.EntityID,
		idpIssuer:        item.IdpIssuer,
		callbackURL:      item.CallbackURL,
		audience:         item.EntityID,
		idpCert:          item.IdpCertificates,
		privateKey:       item.PrivateKey,
		publicCert:       item.PublicCertificate,
		decryptionPvk:    item.DecryptionPrivateKey,
		validateAlways:   !unsolicited,
		cache:            cache,
		generateUniqueID: generate,
		now:              s.now,
	}}
}

// Begin starts an SP-initiated sign-in: the IdP redirect URL, the RelayState, and the browser binding. A linking
// credential links the IdP account to its recently authenticated identity; returnTo (nil or core.Undefined: none) is
// a path on this site.
func (s *SamlService) Begin(ctx context.Context, connectionID string, linkingCredential *core.CredentialInput, returnTo any) (*BeginResult, error) {
	item, err := s.connection(ctx, connectionID, nil)
	if err != nil {
		return nil, err
	}
	var path string
	if !core.IsUndefined(returnTo) && returnTo != nil {
		if path, err = returnPath(returnTo); err != nil {
			return nil, err
		}
	}
	requestID := "_" + randomUUID()
	relayState := base64.RawURLEncoding.EncodeToString(randomBytes(32))
	binding := base64.RawURLEncoding.EncodeToString(randomBytes(32))
	var linkingSessionID, linkingIdentityID any = core.Undefined, core.Undefined
	if linkingCredential != nil {
		if s.config.Authenticate == nil {
			return nil, configuration("Linking requires an authenticate callback.")
		}
		principal, err := s.config.Authenticate(ctx, *linkingCredential)
		if err != nil {
			return nil, err
		}
		authenticatedAt, _ := principal.Session.Number("authenticatedAt")
		age := float64(s.now()) - authenticatedAt
		if principal.Identity.Get("tenantId") != item.TenantID || truthy(principal.Identity.Get("rootAdmin")) ||
			principal.Session.Get("kind") != "user" || age < 0 || age > 300_000 {
			return nil, core.NewIamError("RECENT_AUTH_REQUIRED", "Linking requires recent authentication to a non-root identity in this tenant.", 403)
		}
		linkingSessionID = principal.Session.Get("id")
		linkingIdentityID = principal.Identity.Get("id")
	}
	var destination string
	err = s.config.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		if err := activeTenant(ctx, tx, item.TenantID); err != nil {
			return err
		}
		url, err := s.newSaml(item, tx, requestID, "", false).authorizeURL(ctx, relayState)
		if err != nil {
			return err
		}
		relay := core.NewObject("id", hashHex(relayState), "tenantId", item.TenantID, "connectionId", item.ID,
			"requestId", requestID, "bindingHash", hashHex(binding), "expiresAt", float64(s.now()+600_000),
			"linkingSessionId", linkingSessionID, "linkingIdentityId", linkingIdentityID)
		if path != "" {
			relay.Set("returnTo", path)
		}
		if _, err := tx.Insert(ctx, "samlRelays", relay); err != nil {
			return err
		}
		destination = url
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &BeginResult{URL: destination, RelayState: relayState, Binding: binding}, nil
}

// Callback validates a posted SAML response for an SP-initiated sign-in and completes it.
func (s *SamlService) Callback(ctx context.Context, connectionID string, input CallbackInput) (any, error) {
	result, _, err := s.consume(ctx, connectionID, input)
	return result, err
}

// consume is Callback, also returning the returnTo path the sign-in was started with ("" when none).
func (s *SamlService) consume(ctx context.Context, connectionID string, input CallbackInput) (any, string, error) {
	item, err := s.connection(ctx, connectionID, nil)
	if err != nil {
		return nil, "", err
	}
	if input.Binding == "" || input.RelayState == "" || core.UTF16Len(input.RelayState) > 512 || core.UTF16Len(input.SamlResponse) > 1_400_000 {
		return nil, "", samlInvalid("Invalid SAML response.")
	}
	var result any
	var returnTo string
	err = s.config.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		if err := activeTenant(ctx, tx, item.TenantID); err != nil {
			return err
		}
		relay, err := tx.Get(ctx, "samlRelays", hashHex(input.RelayState))
		if err != nil {
			return err
		}
		expiresAt, _ := relay.Number("expiresAt")
		if relay == nil || relay.Get("tenantId") != item.TenantID || relay.Get("connectionId") != item.ID ||
			expiresAt <= float64(s.now()) ||
			subtle.ConstantTimeCompare([]byte(str(relay, "bindingHash")), []byte(hashHex(input.Binding))) != 1 {
			return samlInvalid("Invalid, expired, or replayed SAML login.")
		}
		requestID := str(relay, "requestId")
		xml := decodeUTF8(nodeBase64(input.SamlResponse))
		if err := ValidateSamlEnvelope(xml, item.CallbackURL, &requestID, item.RequireEncryptedAssertions); err != nil {
			return err
		}
		validated, err := s.newSaml(item, tx, "", requestID, false).validatePostResponse(ctx, input.SamlResponse)
		if err != nil {
			return err
		}
		profile := validated.profile
		if profile == nil || validated.loggedOut || profile.Get("issuer") != item.IdpIssuer || !truthy(profile.Get("nameID")) {
			return samlInvalid("Invalid SAML identity.")
		}
		// Node-SAML decrypts and validates the assertion before exposing this XML.
		if validated.assertion != "" {
			document, err := ParseXML(validated.assertion)
			if err != nil {
				return err
			}
			for _, subject := range document.ElementsByTagNameNS(assertionNamespace, "SubjectConfirmationData") {
				if subject.Attribute("Recipient") != item.CallbackURL {
					return samlInvalid("SAML assertion recipient is invalid.")
				}
			}
		}
		if err := tx.Delete(ctx, "samlRelays", str(relay, "id")); err != nil {
			return err
		}
		finished, err := s.finish(ctx, item, profile, relay)
		if err != nil {
			return err
		}
		result = finished
		returnTo = str(relay, "returnTo")
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return result, returnTo, nil
}

// finish hands a validated SAML identity to the host, with a trusted-domain email and mapped attributes.
func (s *SamlService) finish(ctx context.Context, item *SamlConnection, profile *core.Object, relay *core.Object) (any, error) {
	email := nullish(profile.Get("email"), profile.Get("mail"), profile.Get("urn:oid:0.9.2342.19200300.100.1.3"))
	emailText, isText := email.(string)
	verified := false
	if isText && emailShape.MatchString(emailText) {
		domain := core.JSLower(strings.SplitN(emailText, "@", 3)[1])
		for _, trusted := range item.TrustedEmailDomains {
			if core.JSLower(trusted) == domain {
				verified = true
				break
			}
		}
	}
	var attributes *core.Object
	hasAttributes := false
	if item.MapAttributes != nil {
		attributes = item.MapAttributes(profile)
		hasAttributes = attributes != nil
	}
	providerID := item.ProviderID
	if providerID == "" {
		providerID = item.ID
	}
	input := core.NewObject("tenantId", item.TenantID, "providerId", providerID, "issuer", item.IdpIssuer,
		"subject", profile.Get("nameID"))
	if isText {
		input.Set("email", emailText)
	} else {
		input.SetRaw("email", core.Undefined)
	}
	input.Set("emailVerified", verified)
	if name, ok := profile.Get("displayName").(string); ok {
		input.Set("name", name)
	} else {
		input.SetRaw("name", core.Undefined)
	}
	if relay != nil && truthy(relay.Get("linkingSessionId")) {
		input.Set("linkingSessionId", relay.Get("linkingSessionId"))
		input.SetRaw("linkingIdentityId", relay.Get("linkingIdentityId"))
	}
	if hasAttributes {
		input.Set("attributes", attributes)
	}
	if truthy(item.TrustScimProvisioned) {
		input.Set("trustScimProvisioned", item.TrustScimProvisioned)
	}
	return s.config.CompleteAuthentication(ctx, input)
}

// answersRequest reports whether a base64 SAML response carries InResponseTo (SP-initiated). Unparseable input
// counts as solicited.
func answersRequest(samlResponse string) bool {
	xml := decodeUTF8(nodeBase64(samlResponse))
	if core.UTF16Len(xml) > 1024*1024 || unsafeXML.MatchString(xml) {
		return true
	}
	doc, err := ParseXML(xml)
	if err != nil {
		return true
	}
	root := doc.DocumentElement()
	return root == nil || root.HasAttribute("InResponseTo")
}

// IdpInitiated accepts an IdP-initiated response for a connection with AllowIdpInitiated: the same signature,
// issuer, audience, destination, recipient, and age checks as SP-initiated responses, no InResponseTo, and each
// assertion ID accepted only once.
func (s *SamlService) IdpInitiated(ctx context.Context, connectionID, samlResponse string) (any, error) {
	item, err := s.connection(ctx, connectionID, nil)
	if err != nil {
		return nil, err
	}
	if !item.AllowIdpInitiated || core.UTF16Len(samlResponse) > 1_400_000 {
		return nil, samlInvalid("Unsolicited SAML responses are not accepted.")
	}
	var result any
	err = s.config.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		if err := activeTenant(ctx, tx, item.TenantID); err != nil {
			return err
		}
		xml := decodeUTF8(nodeBase64(samlResponse))
		if err := ValidateSamlEnvelope(xml, item.CallbackURL, nil, item.RequireEncryptedAssertions); err != nil {
			return err
		}
		validated, err := s.newSaml(item, tx, "", "", true).validatePostResponse(ctx, samlResponse)
		if err != nil {
			return err
		}
		profile := validated.profile
		if profile == nil || validated.loggedOut || profile.Get("issuer") != item.IdpIssuer || !truthy(profile.Get("nameID")) {
			return samlInvalid("Invalid SAML identity.")
		}
		var document *Node
		if validated.assertion != "" {
			if document, err = ParseXML(validated.assertion); err != nil {
				return err
			}
		}
		assertionID := ""
		if document != nil {
			assertionID = document.DocumentElement().Attribute("ID")
		}
		if document == nil || assertionID == "" {
			return samlInvalid("The assertion has no identifier.")
		}
		// Node-SAML applies its age limit only when <Conditions> carries times, so the assertion's own IssueInstant
		// bounds it instead: accepted only within the maximum age (plus clock skew), which the single-use record
		// outlives.
		now := float64(s.now())
		issued := dateParse(document.DocumentElement().Attribute("IssueInstant"))
		if issued != issued || issued > now+30_000 || now-issued > 330_000 {
			return samlInvalid("The assertion is too old or not yet valid.")
		}
		for _, subject := range document.ElementsByTagNameNS(assertionNamespace, "SubjectConfirmationData") {
			if subject.Attribute("Recipient") != item.CallbackURL || subject.HasAttribute("InResponseTo") {
				return samlInvalid("SAML assertion recipient is invalid.")
			}
		}
		// One use per assertion for longer than an assertion can be accepted (maximum age plus clock skew).
		current := float64(s.now())
		seen, err := tx.Find(ctx, "samlAssertions", core.NewObject("connectionId", item.ID), nil)
		if err != nil {
			return err
		}
		for _, record := range seen {
			if expiresAt, _ := record.Number("expiresAt"); expiresAt <= current {
				if err := tx.Delete(ctx, "samlAssertions", str(record, "id")); err != nil {
					return err
				}
			}
		}
		key := hashHex(item.TenantID + ":" + item.ID + ":" + assertionID)
		used, err := tx.Get(ctx, "samlAssertions", key)
		if err != nil {
			return err
		}
		if used != nil {
			return samlInvalid("The assertion was already used.")
		}
		if _, err := tx.Insert(ctx, "samlAssertions", core.NewObject("id", key, "tenantId", item.TenantID,
			"connectionId", item.ID, "value", "", "createdAt", current, "expiresAt", current+600_000)); err != nil {
			return err
		}
		finished, err := s.finish(ctx, item, profile, nil)
		if err != nil {
			return err
		}
		result = finished
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetMetadata is the signed SP metadata of any available connection, configured or tenant-managed.
func (s *SamlService) GetMetadata(ctx context.Context, connectionID string) (string, error) {
	item, err := s.connection(ctx, connectionID, nil)
	if err != nil {
		return "", err
	}
	return s.newSaml(item, s.config.Store, "", "", false).serviceProviderMetadata(item.DecryptionCertificate, item.PublicCertificate)
}

// Metadata is the signed SP metadata of a configured connection; GetMetadata also serves tenant-managed ones.
func (s *SamlService) Metadata(connectionID string) (string, error) {
	item, err := s.staticConnection(connectionID)
	if err != nil {
		return "", err
	}
	return s.newSaml(item, s.config.Store, "", "", false).serviceProviderMetadata(item.DecryptionCertificate, item.PublicCertificate)
}

// CreateConnection adds a tenant's identity provider (`iam:saml:connections:create` on `saml/{id}`). input is
// ManagedSamlConnectionInput plus tenantId and an optional id.
func (s *SamlService) CreateConnection(ctx context.Context, credential core.CredentialInput, input *core.Object) (*core.Object, error) {
	idValue := nullish(get(input, "id"))
	id := ""
	if core.IsUndefined(idValue) {
		id = "saml-" + hex.EncodeToString(randomBytes(6))
	} else {
		text, ok := idValue.(string)
		if !ok || !connectionName.MatchString(text) {
			return nil, core.NewIamError("INVALID_INPUT", "Connection IDs are 2-63 lowercase letters, digits, and hyphens.")
		}
		id = text
	}
	if !connectionName.MatchString(id) {
		return nil, core.NewIamError("INVALID_INPUT", "Connection IDs are 2-63 lowercase letters, digits, and hyphens.")
	}
	tenantID, _ := get(input, "tenantId").(string)
	principal, err := s.manager(ctx, credential, "iam:saml:connections:create", tenantID, id)
	if err != nil {
		return nil, err
	}
	values, err := s.settings(input, nil)
	if err != nil {
		return nil, err
	}
	// A fresh provider key links no account yet; the host still requires a recent sign-in to add a trust anchor.
	providerKey := "saml:" + id + ":" + base64.RawURLEncoding.EncodeToString(randomBytes(12))
	if s.config.AssertTrustChange != nil {
		if err := s.config.AssertTrustChange(ctx, credential, tenantID, providerKey); err != nil {
			return nil, err
		}
	}
	return core.Transact(ctx, s.config.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		if err := activeTenant(ctx, tx, tenantID); err != nil {
			return nil, err
		}
		existing, err := tx.Get(ctx, "samlConnections", id)
		if err != nil {
			return nil, err
		}
		if s.connections[id] != nil || existing != nil {
			return nil, core.NewIamError("CONFLICT", "A SAML connection with this ID already exists.", 409)
		}
		now := float64(s.now())
		record := core.NewObject("id", id, "tenantId", tenantID).Spread(values)
		record.Set("providerKey", providerKey)
		record.Set("createdAt", now)
		record.Set("updatedAt", now)
		if _, err := tx.Insert(ctx, "samlConnections", record); err != nil {
			return nil, err
		}
		if err := s.audit(ctx, tx, principal, tenantID, "iam:saml:CreateConnection", id); err != nil {
			return nil, err
		}
		return s.summary(record)
	})
}

// ListConnections lists the tenant's managed connections (`iam:saml:connections:read` on `saml/*`).
func (s *SamlService) ListConnections(ctx context.Context, credential core.CredentialInput, tenantID string) ([]*core.Object, error) {
	if _, err := s.manager(ctx, credential, "iam:saml:connections:read", tenantID, "*"); err != nil {
		return nil, err
	}
	records, err := s.config.Store.Find(ctx, "samlConnections", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	summaries := make([]*core.Object, 0, len(records))
	for _, record := range records {
		summary, err := s.summary(record)
		if err != nil {
			return nil, err
		}
		summaries = append(summaries, summary)
	}
	sort.SliceStable(summaries, func(i, j int) bool {
		a, b := str(summaries[i], "name"), str(summaries[j], "name")
		if a != b {
			return compareUTF16(a, b) < 0
		}
		return compareUTF16(str(summaries[i], "id"), str(summaries[j], "id")) < 0
	})
	return summaries, nil
}

// GetConnection reads one managed connection.
func (s *SamlService) GetConnection(ctx context.Context, credential core.CredentialInput, tenantID, connectionID string) (*core.Object, error) {
	if _, err := s.manager(ctx, credential, "iam:saml:connections:read", tenantID, connectionID); err != nil {
		return nil, err
	}
	record, err := s.managed(ctx, s.config.Store, tenantID, connectionID)
	if err != nil {
		return nil, err
	}
	return s.summary(record)
}

// UpdateConnection changes a managed connection, for example new IdP certificates during rollover or refreshed
// metadata. Disabling it stops new sign-ins at once. input is a partial ManagedSamlConnectionInput plus tenantId and
// connectionId.
func (s *SamlService) UpdateConnection(ctx context.Context, credential core.CredentialInput, input *core.Object) (*core.Object, error) {
	tenantID, _ := get(input, "tenantId").(string)
	connectionID, _ := get(input, "connectionId").(string)
	principal, err := s.manager(ctx, credential, "iam:saml:connections:update", tenantID, connectionID)
	if err != nil {
		return nil, err
	}
	// Whoever changes what the connection trusts can sign in as every account linked through it.
	before, err := s.managed(ctx, s.config.Store, tenantID, connectionID)
	if err != nil {
		return nil, err
	}
	next, err := s.settings(input, before)
	if err != nil {
		return nil, err
	}
	widened := trustWidened(before, next)
	if widened && s.config.AssertTrustChange != nil {
		providerID := str(before, "providerKey")
		if providerID == "" {
			providerID = str(before, "id")
		}
		if err := s.config.AssertTrustChange(ctx, credential, tenantID, providerID); err != nil {
			return nil, err
		}
	}
	return core.Transact(ctx, s.config.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		current, err := s.managed(ctx, tx, tenantID, connectionID)
		if err != nil {
			return nil, err
		}
		values, err := s.settings(input, current)
		if err != nil {
			return nil, err
		}
		if trustWidened(current, values) && (!widened || !core.StrictEquals(current.Get("updatedAt"), before.Get("updatedAt"))) {
			return nil, core.NewIamError("CONFLICT", "The connection changed while it was being updated; try again.", 409)
		}
		record := current.Spread(values)
		record.Set("updatedAt", float64(s.now()))
		if _, err := tx.Put(ctx, "samlConnections", record); err != nil {
			return nil, err
		}
		if err := s.audit(ctx, tx, principal, tenantID, "iam:saml:UpdateConnection", str(current, "id")); err != nil {
			return nil, err
		}
		return s.summary(record)
	})
}

// DeleteConnection removes a managed connection, its pending sign-ins and the account links made through it.
func (s *SamlService) DeleteConnection(ctx context.Context, credential core.CredentialInput, tenantID, connectionID string) error {
	principal, err := s.manager(ctx, credential, "iam:saml:connections:delete", tenantID, connectionID)
	if err != nil {
		return err
	}
	return s.config.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		current, err := s.managed(ctx, tx, tenantID, connectionID)
		if err != nil {
			return err
		}
		id := str(current, "id")
		if err := tx.Delete(ctx, "samlConnections", id); err != nil {
			return err
		}
		relays, err := tx.Find(ctx, "samlRelays", core.NewObject("connectionId", id), nil)
		if err != nil {
			return err
		}
		for _, relay := range relays {
			if err := tx.Delete(ctx, "samlRelays", str(relay, "id")); err != nil {
				return err
			}
		}
		// Connections from before provider keys share their ID with the links; only this IdP's own links go.
		providerKey := current.Get("providerKey")
		providerID := nullish(providerKey, current.Get("id"))
		links, err := tx.Find(ctx, "externalIdentities", core.NewObject("tenantId", current.Get("tenantId"), "providerId", providerID), nil)
		if err != nil {
			return err
		}
		for _, link := range links {
			if truthy(providerKey) || link.Get("issuer") == current.Get("idpIssuer") {
				if err := tx.Delete(ctx, "externalIdentities", str(link, "id")); err != nil {
					return err
				}
			}
		}
		return s.audit(ctx, tx, principal, tenantID, "iam:saml:DeleteConnection", id)
	})
}

// Logout revokes the local IAM session; upstream SAML sessions are not modified.
func (s *SamlService) Logout(ctx context.Context, credential core.CredentialInput) (any, error) {
	if s.config.RevokeSession == nil {
		return nil, configuration("Local logout callback is required.")
	}
	return s.config.RevokeSession(ctx, credential)
}

// readAll reads a request body.
func readAll(r *http.Request) ([]byte, error) { return io.ReadAll(r.Body) }

func utf8Valid(value string) bool { return utf8.ValidString(value) }

// --- HTTP ---------------------------------------------------------------------------------------------------------

// Response is a fetch-style answer.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

func jsonResponse(value any, status int, headers map[string]string) (*Response, error) {
	text, ok, err := core.Stringify(value)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("Value is not JSON serializable")
	}
	header := http.Header{}
	for key, item := range headers {
		header.Set(key, item)
	}
	header.Set("Content-Type", "application/json")
	return &Response{Status: status, Header: header, Body: []byte(text)}, nil
}

func mustJSON(value any, status int, headers map[string]string) *Response {
	response, err := jsonResponse(value, status, headers)
	if err != nil {
		response, _ = jsonResponse(core.NewObject("error", "SAML_INVALID"), 401, nil)
	}
	return response
}

// requestURL is new URL(request.url) for a server request.
func requestURL(r *http.Request) (*auth.FetchURL, error) {
	if r.URL.IsAbs() {
		return parseURL(r.URL.String())
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return parseURL(scheme + "://" + r.Host + r.URL.RequestURI())
}

// cookieValue reads a cookie the way the TypeScript handler does.
func cookieValue(header http.Header, name string) string {
	values := header.Values("Cookie")
	if len(values) == 0 {
		return ""
	}
	for _, part := range strings.Split(strings.Join(values, "; "), ";") {
		part = core.JSTrim(part)
		if strings.HasPrefix(part, name+"=") {
			return part[len(name)+1:]
		}
	}
	return ""
}

func headerValue(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) == 0 {
		return "", false
	}
	return strings.Join(values, ", "), true
}

// Handler is the HTTP mount (ProtocolService.Handler): it answers the SAML routes and returns false for others.
func (s *SamlService) Handler(w http.ResponseWriter, r *http.Request) bool {
	response := s.Handle(r)
	if response == nil {
		return false
	}
	for key, values := range response.Header {
		w.Header()[key] = values
	}
	w.WriteHeader(response.Status)
	_, _ = w.Write(response.Body)
	return true
}

// Handle is the fetch-style handler: an answer, or nil when the request is not a SAML route.
func (s *SamlService) Handle(r *http.Request) *Response {
	target, err := requestURL(r)
	if err != nil {
		return nil
	}
	pathname := target.EscapedPath()
	if r.Method == http.MethodPost {
		for _, id := range s.order {
			if item := s.connections[id]; item.CallbackURL == urlOrigin(target)+pathname {
				return s.acs(r.Context(), item, r)
			}
		}
	}
	if !strings.HasPrefix(pathname, s.basePath+"/") {
		return nil
	}
	response, err := s.route(r, target, pathname)
	if err != nil {
		var known *core.IamError
		if errors.As(err, &known) {
			return mustJSON(core.NewObject("error", known.Code), known.Status, nil)
		}
		return mustJSON(core.NewObject("error", "SAML_FAILED"), 401, nil)
	}
	return response
}

func (s *SamlService) route(r *http.Request, target *auth.FetchURL, pathname string) (*Response, error) {
	ctx := r.Context()
	parts := strings.Split(pathname[len(s.basePath)+1:], "/")
	id, err := decodeURIComponent(parts[0])
	if err != nil {
		return nil, err
	}
	if r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "acs" {
		var item *SamlConnection
		if s.connections[id] == nil {
			item, _ = s.connection(ctx, id, nil)
		}
		if item == nil {
			return mustJSON(core.NewObject("error", "NOT_FOUND"), 404, nil), nil
		}
		return s.acs(ctx, item, r), nil
	}
	if r.Method == http.MethodGet && len(parts) == 2 && parts[1] == "metadata" {
		item, err := s.connection(ctx, id, nil)
		if err != nil {
			return nil, err
		}
		metadata, err := s.newSaml(item, s.config.Store, "", "", false).serviceProviderMetadata(item.DecryptionCertificate, item.PublicCertificate)
		if err != nil {
			return nil, err
		}
		return &Response{Status: 200, Header: http.Header{"Content-Type": {"application/samlmetadata+xml"}}, Body: []byte(metadata)}, nil
	}
	if (r.Method != http.MethodGet && r.Method != http.MethodPost) || len(parts) != 2 || parts[1] != "login" {
		return mustJSON(core.NewObject("error", "NOT_FOUND"), 404, nil), nil
	}
	if r.Method == http.MethodPost {
		item, err := s.connection(ctx, id, nil)
		if err != nil {
			return nil, err
		}
		origin, hasOrigin := headerValue(r.Header, "Origin")
		trusted := s.config.TrustedOrigins
		if trusted == nil {
			if parsed, err := parseURL(item.CallbackURL); err == nil {
				trusted = []string{urlOrigin(parsed)}
			}
		}
		marker, _ := headerValue(r.Header, "X-Better-IAM")
		contentType, _ := headerValue(r.Header, "Content-Type")
		if !hasOrigin || origin == "" || !contains(trusted, origin) || marker != "1" || !strings.HasPrefix(contentType, "application/json") {
			return nil, core.NewIamError("CSRF", "Linking requires a trusted Origin and X-Better-IAM header.", 403)
		}
	}
	var returnTo any = core.Undefined
	if value, ok := parseSearchParams(target.RawQuery).Get("returnTo"); ok {
		returnTo = value
	}
	var linking *core.CredentialInput
	if r.Method == http.MethodPost {
		linking = &core.CredentialInput{Headers: r.Header}
	}
	result, err := s.Begin(ctx, id, linking, returnTo)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{
		"Cache-Control": "no-store",
		"Set-Cookie":    "__Host-better-iam-saml-" + hashHex(id)[:12] + "=" + result.Binding + "; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=600",
	}
	if r.Method == http.MethodPost {
		return jsonResponse(core.NewObject("url", result.URL), 200, headers)
	}
	header := http.Header{}
	for key, value := range headers {
		header.Set(key, value)
	}
	header.Set("Location", result.URL)
	return &Response{Status: 302, Header: header}, nil
}

// decodeURIComponent is the JavaScript built-in (a URIError for malformed escapes).
func decodeURIComponent(value string) (string, error) {
	if !strings.Contains(value, "%") {
		return value, nil
	}
	decoded, err := url.PathUnescape(strings.ReplaceAll(value, "+", "%2B"))
	if err != nil || !utf8Valid(decoded) {
		return "", errors.New("URI malformed")
	}
	return decoded, nil
}

// acs is the assertion consumer service: HTTP-POST binding, browser-binding cookie, then Callback.
func (s *SamlService) acs(ctx context.Context, item *SamlConnection, r *http.Request) *Response {
	response, err := s.acsInner(ctx, item, r)
	if err == nil {
		return response
	}
	headers := map[string]string{"Cache-Control": "no-store"}
	// The specific code only goes to the configured error page; the JSON answer stays generic.
	if s.errorURL != nil && *s.errorURL != "" {
		code := "SAML_INVALID"
		var known *core.IamError
		if errors.As(err, &known) && errorCode.MatchString(known.Code) {
			code = known.Code
		}
		base, _ := url.Parse("https://placeholder.invalid")
		reference, parseErr := url.Parse(*s.errorURL)
		if parseErr == nil {
			resolved := base.ResolveReference(reference)
			params := parseSearchParams(resolved.RawQuery)
			params.Set("error", code)
			search := "?" + params.String()
			hash := ""
			if resolved.Fragment != "" {
				hash = "#" + resolved.EscapedFragment()
			}
			if strings.HasPrefix(*s.errorURL, "/") {
				headers[redirectHeader] = resolved.EscapedPath() + search + hash
			} else {
				headers[redirectHeader] = urlWithSearch(resolved, params.String())
			}
		}
	}
	return mustJSON(core.NewObject("error", "SAML_INVALID"), 401, headers)
}

func (s *SamlService) acsInner(ctx context.Context, item *SamlConnection, r *http.Request) (*Response, error) {
	contentType, _ := headerValue(r.Header, "Content-Type")
	if !strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		return nil, core.NewIamError("SAML_INVALID", "SAML POST binding is required.", 415)
	}
	var body []byte
	if r.Body != nil {
		data, err := readAll(r)
		if err != nil {
			return nil, err
		}
		body = data
	}
	text := decodeUTF8(body)
	if core.UTF16Len(text) > 2_000_000 {
		return nil, core.NewIamError("SAML_INVALID", "SAML response is too large.", 413)
	}
	form := parseSearchParams(text)
	if len(form.GetAll("SAMLResponse")) != 1 || len(form.GetAll("RelayState")) > 1 {
		return nil, core.NewIamError("SAML_INVALID", "Invalid SAML POST parameters.", 400)
	}
	samlResponse, _ := form.Get("SAMLResponse")
	// Responses that answer no request are IdP-initiated; only connections that opt in accept them.
	if item.AllowIdpInitiated && !answersRequest(samlResponse) {
		result, err := s.IdpInitiated(ctx, item.ID, samlResponse)
		if err != nil {
			return nil, err
		}
		return s.signedIn(item, result, "", map[string]string{"Cache-Control": "no-store"})
	}
	if len(form.GetAll("RelayState")) != 1 {
		return nil, core.NewIamError("SAML_INVALID", "Invalid SAML POST parameters.", 400)
	}
	relayState, _ := form.Get("RelayState")
	cookieName := "__Host-better-iam-saml-" + hashHex(item.ID)[:12]
	binding := cookieValue(r.Header, cookieName)
	result, returnTo, err := s.consume(ctx, item.ID, CallbackInput{SamlResponse: samlResponse, RelayState: relayState, Binding: binding})
	if err != nil {
		return nil, err
	}
	return s.signedIn(item, result, returnTo, map[string]string{
		"Cache-Control": "no-store",
		"Set-Cookie":    cookieName + "=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0",
	})
}

// signedIn is the ACS answer for a completed SAML exchange: the host's result as JSON and, with afterSignIn, the
// redirect hint the host's protocol mount turns into a 303. An MFA challenge goes to mfaUrl in the fragment.
func (s *SamlService) signedIn(item *SamlConnection, result any, returnTo string, headers map[string]string) (*Response, error) {
	if value, ok := result.(*core.Object); ok && value != nil && s.afterSignIn != nil && *s.afterSignIn != "" {
		challenge, isChallenge := value.Get("challenge").(string)
		if value.Get("mfaRequired") == true && isChallenge {
			_ = challenge
			fragment := &searchParams{pairs: [][2]string{{"tenantId", item.TenantID}}}
			for _, key := range value.Keys() {
				switch field := value.Get(key).(type) {
				case string:
					fragment.Set(key, field)
				case bool:
					if field {
						fragment.Set(key, "true")
					} else {
						fragment.Set(key, "false")
					}
				}
			}
			if returnTo != "" {
				fragment.Set("returnTo", returnTo)
			}
			target := *s.afterSignIn
			if s.mfaURL != nil && *s.mfaURL != "" {
				target = *s.mfaURL
			}
			headers[redirectHeader] = target + "#" + fragment.String()
		} else if _, isToken := value.Get("token").(string); isToken {
			if returnTo != "" {
				headers[redirectHeader] = returnTo
			} else {
				headers[redirectHeader] = *s.afterSignIn
			}
		}
	}
	return jsonResponse(result, 200, headers)
}
