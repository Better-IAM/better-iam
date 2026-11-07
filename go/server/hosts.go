package server

// Port of packages/server/src/hosts.ts: the option types, normalizeHost, WrongRegionError, the
// configuration resolvers resolveConfig uses (resolveRegionConfig, resolveHostConfig), and the host service
// (createHosts: resolving request addresses, sign-in URLs, region pinning).

import (
	"context"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// HostOptions are organization sign-in addresses: subdomains built from each organization's alias
// (`acme.signin.example.com`), optionally per region, and verified custom hostnames (`login.acme.com`).
type HostOptions struct {
	// Patterns are hostname templates. `{tenant}` stands for an organization's alias (its slug) and `{region}` for
	// one of the configured regions. The first template is the canonical address used in sign-in URLs and email links.
	Patterns []string `json:"patterns,omitempty"`
	// CustomHostnames lets organizations verify hostnames of their own with a DNS TXT record (default false).
	CustomHostnames *bool `json:"customHostnames,omitempty"`
	// CnameTarget is the hostname organizations point their custom hostname at with a CNAME record.
	CnameTarget *string `json:"cnameTarget,omitempty"`
	// SignInPath is the path of the sign-in page on an organization's address (default `/`).
	SignInPath *string `json:"signInPath,omitempty"`
	// ForwardedHost reads the address from X-Forwarded-Host before Host (only behind a proxy you control).
	ForwardedHost *bool `json:"forwardedHost,omitempty"`
}

// RegionSettings is one region of RegionOptions.Regions.
type RegionSettings struct {
	BaseURL *string `json:"baseURL,omitempty"`
	Label   *string `json:"label,omitempty"`
}

// RegionOptions describes where organizations live when a deployment runs in several regions.
type RegionOptions struct {
	// Current is this deployment's region, for example `us-east-1`.
	Current string `json:"current"`
	// Regions lists every region organizations can live in, with the base URL of that region's deployment and a label.
	Regions map[string]RegionSettings `json:"regions"`
	// Locate returns the region an organization alias lives in when this region's database does not know it (nil:
	// unknown), for deployments whose regions keep separate databases.
	Locate func(ctx context.Context, alias string) (*string, error) `json:"-"`
}

// TenantHostname is a hostname an organization claims as its own sign-in address (collection tenantHostnames).
type TenantHostname struct {
	core.StoredRecord
	Hostname          string   `json:"hostname"`
	Status            string   `json:"status"`
	VerificationToken string   `json:"verificationToken"`
	Primary           *bool    `json:"primary,omitempty"`
	CreatedAt         float64  `json:"createdAt"`
	CreatedBy         string   `json:"createdBy"`
	VerifiedAt        *float64 `json:"verifiedAt,omitempty"`
	LastCheckedAt     *float64 `json:"lastCheckedAt,omitempty"`
}

// HostnameOwner is the global ownership record of a hostname (id = the hostname).
type HostnameOwner struct {
	core.StoredRecord
	HostnameID string  `json:"hostnameId"`
	VerifiedAt float64 `json:"verifiedAt"`
}

// HostMatch is the organization an address belongs to.
type HostMatch struct {
	TenantID string `json:"tenantId"`
	Name     string `json:"name"`
	Slug     string `json:"slug,omitempty"`
	// Hostname is the hostname the organization was found by, lowercase, with its port when it has one.
	Hostname string `json:"hostname"`
	// Via is `pattern` for a subdomain built from the alias, `custom` for a verified custom hostname.
	Via string `json:"via"`
	// HostRegion is the region named by the address itself, if any.
	HostRegion string `json:"hostRegion,omitempty"`
}

// WrongRegionError means the organization is served by another region's deployment (WRONG_REGION, 421). Location is
// its sign-in URL there, when one can be built. It unwraps to the IamError.
type WrongRegionError struct {
	*core.IamError
	Region   string
	Location *string
}

func (e *WrongRegionError) Unwrap() error { return e.IamError }

// Name is the JavaScript error name.
func (e *WrongRegionError) Name() string { return "WrongRegionError" }

// NewWrongRegionError builds the error; organization defaults to "This organization".
func NewWrongRegionError(region string, location *string, organization ...string) *WrongRegionError {
	who := "This organization"
	if len(organization) > 0 {
		who = organization[0]
	}
	message := who + " is served from the " + region + " region"
	if location != nil && *location != "" {
		message = who + " signs in at " + *location
	}
	return &WrongRegionError{IamError: core.NewIamError("WRONG_REGION", message, 421), Region: region, Location: location}
}

// CompiledPattern is one compiled hostname template.
type CompiledPattern struct {
	Source    string
	Regex     *regexp.Regexp
	HasRegion bool
	// Suffix is everything after the last placeholder when it starts a new label (`.signin.example.com`), else ''.
	Suffix string
	// Fill builds the address of an alias in a region (nil: the current region).
	Fill func(alias string, region *string) string
}

// ResolvedHostConfig is the validated `hosts` option.
type ResolvedHostConfig struct {
	Patterns        []CompiledPattern
	CustomHostnames bool
	CnameTarget     string
	SignInPath      string
	ForwardedHost   bool
	// Enabled is true when any organization address can exist, so requests must be resolved.
	Enabled bool
}

// ResolvedRegionConfig is the validated `regions` option.
type ResolvedRegionConfig struct {
	Current string
	// Names lists the regions in option order; Regions holds their settings.
	Names   []string
	Regions map[string]RegionSettings
	Locate  func(ctx context.Context, alias string) (*string, error)
}

const aliasSource = `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?`

var regionName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// hostnameLabel is /^(?!-)[a-z0-9-]{1,63}(?<!-)$/.
func hostnameLabel(part string) bool {
	if len(part) < 1 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
		return false
	}
	for i := 0; i < len(part); i++ {
		c := part[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func loopbackHost(hostname string) bool {
	return hostname == "localhost" || strings.HasSuffix(hostname, ".localhost") || hostname == "127.0.0.1" ||
		hostname == "[::1]"
}

var hostShape = regexp.MustCompile(`^(?:[a-z0-9-]+(?:\.[a-z0-9-]+)*|\[[0-9a-f:]+\])(?::\d{1,5})?$`)
var portSuffix = regexp.MustCompile(`^:\d+$`)

// NormalizeHost is a request's address, lowercase and without a trailing dot, or "" when it is not a plain
// host[:port].
func NormalizeHost(value string) string {
	if value == "" {
		return ""
	}
	host := core.JSLower(core.JSTrim(value))
	// .replace(/\.(?=:\d+$|$)/, ''): the first dot followed by a port at the end, or by the end.
	for i := 0; i < len(host); i++ {
		if host[i] == '.' && (i+1 == len(host) || portSuffix.MatchString(host[i+1:])) {
			host = host[:i] + host[i+1:]
			break
		}
	}
	if hostShape.MatchString(host) && utf16Len(host) <= 260 {
		return host
	}
	return ""
}

// ResolveRegionConfig validates `options.regions` (a model value) and applies the defaults; nil for a single-region
// deployment. locate is the typed callback (the model value only says whether one is set).
func ResolveRegionConfig(options any, locate func(ctx context.Context, alias string) (*string, error)) (*ResolvedRegionConfig, error) {
	if isUndefined(options) {
		return nil, nil
	}
	invalid := func(detail string) error { return invalidConfig("regions." + detail) }
	if !isPlainObject(options) && !isArray(options) {
		return nil, invalid("options must be an object")
	}
	current := member(options, "current")
	currentName, isString := current.(string)
	if !isString || !regionName.MatchString(currentName) {
		return nil, invalid("current must be a region name such as us-east-1")
	}
	rawRegions := member(options, "regions")
	if !truthy(rawRegions) || typeOf(rawRegions) != "object" {
		return nil, invalid("regions must map each region name to its settings")
	}
	entries := objectEntries(rawRegions)
	if len(entries) == 0 || len(entries) > 64 {
		return nil, invalid("regions must list 1 to 64 regions")
	}
	resolved := &ResolvedRegionConfig{Current: currentName, Regions: map[string]RegionSettings{}}
	for _, entry := range entries {
		name := entry.key
		if !regionName.MatchString(name) {
			return nil, invalid("regions has an invalid region name: " + name)
		}
		value := coalesce(entry.value, core.NewObject())
		if typeOf(value) != "object" {
			return nil, invalid("regions." + name + " must be an object")
		}
		settings := RegionSettings{}
		if baseURL := member(value, "baseURL"); !isUndefined(baseURL) {
			u, err := auth.ParseFetchURL(jsString(baseURL))
			if err != nil {
				return nil, invalid("regions." + name + ".baseURL must be an absolute URL")
			}
			if u.Protocol != "https:" && !(u.Protocol == "http:" && loopbackHost(u.Hostname)) {
				return nil, invalid("regions." + name + ".baseURL must use HTTPS outside localhost")
			}
			url := urlOrigin(u) + strings.TrimSuffix(urlPathname(u), "/")
			settings.BaseURL = &url
		}
		if label := member(value, "label"); !isUndefined(label) {
			text, ok := label.(string)
			if !ok || core.JSTrim(text) == "" || utf16Len(text) > 64 {
				return nil, invalid("regions." + name + ".label must be 1 to 64 characters")
			}
			trimmed := core.JSTrim(text)
			settings.Label = &trimmed
		}
		if _, seen := resolved.Regions[name]; !seen {
			resolved.Names = append(resolved.Names, name)
		}
		resolved.Regions[name] = settings
	}
	if _, ok := resolved.Regions[currentName]; !ok {
		return nil, invalid("current must be one of regions")
	}
	if located := member(options, "locate"); !isUndefined(located) && typeOf(located) != "function" {
		return nil, invalid("locate must be a function")
	}
	resolved.Locate = locate
	return resolved, nil
}

// HostConfigContext is what ResolveHostConfig validates the patterns against.
type HostConfigContext struct {
	BaseURL     *auth.FetchURL
	Regions     *ResolvedRegionConfig
	PasskeyRpID string
}

var placeholderSplit = regexp.MustCompile(`\{tenant\}|\{region\}`)
var portDigits = regexp.MustCompile(`^\d{1,5}$`)
var signInPathPattern = regexp.MustCompile(`^/[\w./~%-]*$`)

// ResolveHostConfig validates `options.hosts` (a model value) against the base URL, the regions, and the passkey RP
// ID, and compiles the patterns.
func ResolveHostConfig(options any, hostContext HostConfigContext) (*ResolvedHostConfig, error) {
	invalid := func(detail string) error { return invalidConfig("hosts." + detail) }
	if !isUndefined(options) && (options == nil || typeOf(options) != "object") {
		return nil, invalid("options must be an object")
	}
	settings := options
	if isUndefined(settings) {
		settings = core.NewObject()
	}
	rawPatterns := member(settings, "patterns")
	patternList, isList := rawPatterns.([]any)
	if !isUndefined(rawPatterns) && (!isList || len(patternList) > 16) {
		return nil, invalid("patterns must be an array of at most 16 templates")
	}
	var regionNames []string
	if hostContext.Regions != nil {
		regionNames = append(regionNames, hostContext.Regions.Names...)
	}
	sort.SliceStable(regionNames, func(i, j int) bool { return utf16Len(regionNames[i]) > utf16Len(regionNames[j]) })
	resolved := &ResolvedHostConfig{}
	for _, item := range patternList {
		raw, ok := item.(string)
		if !ok {
			return nil, invalid("patterns must be strings")
		}
		source := core.JSLower(core.JSTrim(raw))
		if strings.Count(source, "{tenant}") != 1 {
			return nil, invalid("patterns entry " + raw + " must contain {tenant} exactly once")
		}
		if strings.Count(source, "{region}") > 1 {
			return nil, invalid("patterns entry " + raw + " may contain {region} at most once")
		}
		hasRegion := strings.Count(source, "{region}") == 1
		if hasRegion && hostContext.Regions == nil {
			return nil, invalid("patterns entry " + raw + " uses {region}, which needs the regions option")
		}
		sampleRegion := "region"
		if hostContext.Regions != nil {
			sampleRegion = hostContext.Regions.Current
		}
		sample := strings.Replace(strings.Replace(source, "{tenant}", "tenant", 1), "{region}", sampleRegion, 1)
		pieces := strings.Split(sample, ":")
		hostname := pieces[0]
		validTemplate := len(pieces) <= 2 &&
			(len(pieces) < 2 || portDigits.MatchString(pieces[1])) &&
			!strings.ContainsAny(sample, "{}") && hostname != "" && len(strings.Split(hostname, ".")) >= 2
		if validTemplate {
			for _, part := range strings.Split(hostname, ".") {
				if !hostnameLabel(part) {
					validTemplate = false
					break
				}
			}
		}
		if !validTemplate {
			return nil, invalid("patterns entry " + raw + " is not a valid hostname template")
		}
		if hostContext.BaseURL.Protocol != "https:" && !loopbackHost(hostname) {
			return nil, invalid("patterns need an HTTPS baseURL outside localhost")
		}
		if rpID := hostContext.PasskeyRpID; rpID != "" && hostname != rpID && !strings.HasSuffix(hostname, "."+rpID) {
			return nil, invalid("patterns entry " + raw + " must be under the passkey RP ID " + rpID)
		}
		parts := splitKeepingPlaceholders(source)
		var expression strings.Builder
		expression.WriteString("^")
		for _, part := range parts {
			switch part {
			case "{tenant}":
				expression.WriteString("(?P<tenant>" + aliasSource + ")")
			case "{region}":
				quoted := make([]string, len(regionNames))
				for index, name := range regionNames {
					quoted[index] = regexp.QuoteMeta(name)
				}
				expression.WriteString("(?P<region>" + strings.Join(quoted, "|") + ")")
			default:
				expression.WriteString(regexp.QuoteMeta(part))
			}
		}
		expression.WriteString("$")
		last := ""
		if len(parts) > 0 {
			last = parts[len(parts)-1]
		}
		suffix := ""
		if strings.HasPrefix(last, ".") {
			suffix = trailingPort.ReplaceAllString(last, "")
		}
		regions := hostContext.Regions
		pattern := source
		resolved.Patterns = append(resolved.Patterns, CompiledPattern{
			Source:    source,
			Regex:     regexp.MustCompile(expression.String()),
			HasRegion: hasRegion,
			Suffix:    suffix,
			Fill: func(alias string, region *string) string {
				fill := ""
				if region != nil {
					fill = *region
				} else if regions != nil {
					fill = regions.Current
				}
				return strings.Replace(strings.Replace(pattern, "{tenant}", alias, 1), "{region}", fill, 1)
			},
		})
	}
	if custom := member(settings, "customHostnames"); !isUndefined(custom) && typeOf(custom) != "boolean" {
		return nil, invalid("customHostnames must be a boolean")
	}
	if target := member(settings, "cnameTarget"); !isUndefined(target) {
		text, _ := target.(string)
		cname := NormalizeHost(text)
		if cname == "" || strings.Contains(cname, ":") {
			return nil, invalid("cnameTarget must be a hostname such as custom.signin.example.com")
		}
		resolved.CnameTarget = cname
	}
	signInPath := coalesce(member(settings, "signInPath"), "/")
	path, isString := signInPath.(string)
	if !isString || !signInPathPattern.MatchString(path) {
		return nil, invalid("signInPath must be a path starting with /")
	}
	if forwarded := member(settings, "forwardedHost"); !isUndefined(forwarded) && typeOf(forwarded) != "boolean" {
		return nil, invalid("forwardedHost must be a boolean")
	}
	resolved.CustomHostnames = member(settings, "customHostnames") == true
	resolved.SignInPath = path
	resolved.ForwardedHost = member(settings, "forwardedHost") == true
	resolved.Enabled = len(resolved.Patterns) > 0 || resolved.CustomHostnames
	return resolved, nil
}

var trailingPort = regexp.MustCompile(`:\d+$`)

// splitKeepingPlaceholders is source.split(/(\{tenant\}|\{region\})/): the text between placeholders and the
// placeholders themselves, in order.
func splitKeepingPlaceholders(source string) []string {
	var parts []string
	rest := source
	for {
		location := placeholderSplit.FindStringIndex(rest)
		if location == nil {
			parts = append(parts, rest)
			return parts
		}
		parts = append(parts, rest[:location[0]], rest[location[0]:location[1]])
		rest = rest[location[1]:]
	}
}

// objectEntry is one [key, value] pair of Object.entries.
type objectEntry struct {
	key   string
	value any
}

// objectEntries is Object.entries over a model value (strings and arrays enumerate their indexes).
func objectEntries(value any) []objectEntry {
	switch v := value.(type) {
	case *core.Object:
		var out []objectEntry
		v.Entries(func(key string, item any) bool {
			out = append(out, objectEntry{key, item})
			return true
		})
		return out
	case []any:
		out := make([]objectEntry, len(v))
		for index, item := range v {
			out[index] = objectEntry{core.NumberString(float64(index)), item}
		}
		return out
	}
	return nil
}

// HostService is the host and region service of one deployment (hosts.ts createHosts).
type HostService struct {
	server *ServerContext
	// Enabled is true when organization addresses are configured, so requests are resolved and may be pinned.
	Enabled      bool
	baseHost     string
	scheme       string
	ownHostnames map[string]bool
}

// CreateHosts builds the host service of a deployment.
func CreateHosts(server *ServerContext) *HostService {
	config := server.Config
	own := map[string]bool{}
	for _, origin := range append([]string{urlOrigin(config.BaseURL)}, config.TrustedOrigins...) {
		hostname := ""
		if parsed, err := auth.ParseFetchURL(origin); err == nil {
			hostname = parsed.Hostname
		}
		own[hostname] = true
	}
	return &HostService{
		server: server, Enabled: config.Hosts.Enabled, baseHost: urlHost(config.BaseURL),
		scheme: config.BaseURL.Protocol, ownHostnames: own,
	}
}

func (s *HostService) store(tx core.IamStore) core.IamStore {
	if tx == nil {
		return s.server.Store
	}
	return tx
}

// active is the tenant when it and every ancestor are active.
func (s *HostService) active(ctx context.Context, tx core.IamStore, realm *core.Object) (*core.Object, error) {
	if realm == nil || realm.Get("status") != "active" {
		return nil, nil
	}
	chain, err := s.server.Ancestry(ctx, tx, realm)
	if err != nil {
		return nil, err
	}
	for _, item := range chain {
		if item.Get("status") != "active" {
			return nil, nil
		}
	}
	return realm, nil
}

// RegionOf is the home region of a tenant: its own `region`, else its nearest ancestor's ("" for none).
func (s *HostService) RegionOf(ctx context.Context, tx core.IamStore, tenant *core.Object) (string, error) {
	if s.server.Config.Regions == nil {
		return "", nil
	}
	chain, err := s.server.Ancestry(ctx, tx, tenant)
	if err != nil {
		return "", err
	}
	for _, item := range chain {
		if region := item.Get("region"); truthy(region) {
			return jsString(region), nil
		}
	}
	return "", nil
}

// SignInURL is an organization's canonical sign-in URL: its primary custom hostname, else its subdomain, else its
// region's URL ("" when none can be built). target is a tenant record or a tenant ID; tx nil reads the store.
func (s *HostService) SignInURL(ctx context.Context, target any, tx core.IamStore) (string, error) {
	tx = s.store(tx)
	hosts, regions := s.server.Config.Hosts, s.server.Config.Regions
	realm, _ := target.(*core.Object)
	if id, isString := target.(string); isString {
		found, err := tx.Get(ctx, "tenants", id)
		if err != nil {
			return "", err
		}
		realm = found
	}
	if realm == nil {
		return "", nil
	}
	home, err := s.RegionOf(ctx, tx, realm)
	if err != nil {
		return "", err
	}
	if hosts.CustomHostnames {
		records, err := tx.Find(ctx, "tenantHostnames", core.NewObject("tenantId", realm.Get("id")), nil)
		if err != nil {
			return "", err
		}
		for _, record := range records {
			if truthy(record.Get("primary")) && record.Get("status") == "verified" {
				return s.scheme + "//" + jsString(record.Get("hostname")) + hosts.SignInPath, nil
			}
		}
	}
	if slug := realm.Get("slug"); truthy(slug) && len(hosts.Patterns) > 0 {
		var region *string
		if home != "" {
			region = &home
		}
		return s.scheme + "//" + hosts.Patterns[0].Fill(jsString(slug), region) + hosts.SignInPath, nil
	}
	if home != "" && regions != nil {
		if settings, found := regions.Regions[home]; found && settings.BaseURL != nil && *settings.BaseURL != "" {
			path := hosts.SignInPath
			if path == "/" {
				path = ""
			}
			return *settings.BaseURL + path, nil
		}
	}
	return "", nil
}

func (s *HostService) redirectFor(ctx context.Context, realm *core.Object, region string, tx core.IamStore) error {
	location, err := s.SignInURL(ctx, realm, tx)
	if err != nil {
		return err
	}
	var where *string
	if location != "" {
		where = &location
	}
	return NewWrongRegionError(region, where, jsString(realm.Get("name")))
}

// AssertServedHere refuses with WRONG_REGION when the tenant is served by another region (or hostRegion, "" for
// none, names the wrong one).
func (s *HostService) AssertServedHere(ctx context.Context, tx core.IamStore, tenant *core.Object, hostRegion string) error {
	regions := s.server.Config.Regions
	if regions == nil {
		return nil
	}
	home, err := s.RegionOf(ctx, tx, tenant)
	if err != nil {
		return err
	}
	if home == "" {
		home = regions.Current
	}
	if home != regions.Current || (hostRegion != "" && hostRegion != home) {
		return s.redirectFor(ctx, tenant, home, tx)
	}
	return nil
}

// AssertTenantServedHere is AssertServedHere for a tenant ID from a request body; unknown tenants are left to the
// operation to refuse.
func (s *HostService) AssertTenantServedHere(ctx context.Context, tenantID string) error {
	if s.server.Config.Regions == nil {
		return nil
	}
	return s.server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		realm, err := tx.Get(ctx, "tenants", tenantID)
		if err != nil || realm == nil {
			return err
		}
		return s.AssertServedHere(ctx, tx, realm, "")
	})
}

// RemoteAlias is, for an alias this database does not know, the redirect to the region that has it when
// regions.locate finds one (nil otherwise).
func (s *HostService) RemoteAlias(ctx context.Context, alias string) *WrongRegionError {
	regions, hosts := s.server.Config.Regions, s.server.Config.Hosts
	if regions == nil || regions.Locate == nil {
		return nil
	}
	region, err := regions.Locate(ctx, alias)
	if err != nil || region == nil || *region == "" || *region == regions.Current {
		return nil
	}
	settings, known := regions.Regions[*region]
	if !known {
		return nil
	}
	var location *string
	if len(hosts.Patterns) > 0 {
		value := s.scheme + "//" + hosts.Patterns[0].Fill(alias, region) + hosts.SignInPath
		location = &value
	} else if settings.BaseURL != nil && *settings.BaseURL != "" {
		path := hosts.SignInPath
		if path == "/" {
			path = ""
		}
		value := *settings.BaseURL + path
		location = &value
	}
	return NewWrongRegionError(*region, location)
}

// Resolve is the organization an address belongs to: nil for the deployment's own address and hosts it does not
// recognize; NOT_FOUND for a sign-in address of an unknown or inactive organization; WRONG_REGION when the alias lives
// in another region's database. tx nil reads the store.
func (s *HostService) Resolve(ctx context.Context, rawHost string, tx core.IamStore) (*HostMatch, error) {
	hosts := s.server.Config.Hosts
	if !hosts.Enabled {
		return nil, nil
	}
	tx = s.store(tx)
	host := NormalizeHost(rawHost)
	if host == "" || host == s.baseHost {
		return nil, nil
	}
	notFound := func() error { return core.NewIamError("NOT_FOUND", "No organization uses this address", 404) }
	for _, pattern := range hosts.Patterns {
		match := pattern.Regex.FindStringSubmatch(host)
		if match == nil {
			continue
		}
		alias := match[pattern.Regex.SubexpIndex("tenant")]
		record, err := tx.Get(ctx, "tenantAliases", alias)
		if err != nil {
			return nil, err
		}
		var realm *core.Object
		if record != nil {
			found, err := tx.Get(ctx, "tenants", jsString(record.Get("tenantId")))
			if err != nil {
				return nil, err
			}
			if realm, err = s.active(ctx, tx, found); err != nil {
				return nil, err
			}
		}
		if realm == nil {
			if record == nil {
				if elsewhere := s.RemoteAlias(ctx, alias); elsewhere != nil {
					return nil, elsewhere
				}
			}
			return nil, notFound()
		}
		result := &HostMatch{TenantID: jsString(realm.Get("id")), Name: jsString(realm.Get("name")), Slug: alias, Hostname: host, Via: "pattern"}
		if index := pattern.Regex.SubexpIndex("region"); index >= 0 && match[index] != "" {
			result.HostRegion = match[index]
		}
		return result, nil
	}
	if hosts.CustomHostnames {
		hostname := trailingPort.ReplaceAllString(host, "")
		owner, err := tx.Get(ctx, "hostnameOwners", hostname)
		if err != nil {
			return nil, err
		}
		if owner != nil {
			found, err := tx.Get(ctx, "tenants", jsString(owner.Get("tenantId")))
			if err != nil {
				return nil, err
			}
			realm, err := s.active(ctx, tx, found)
			if err != nil {
				return nil, err
			}
			if realm == nil {
				return nil, notFound()
			}
			result := &HostMatch{TenantID: jsString(realm.Get("id")), Name: jsString(realm.Get("name")), Hostname: host, Via: "custom"}
			if slug := realm.Get("slug"); truthy(slug) {
				result.Slug = jsString(slug)
			}
			return result, nil
		}
	}
	return nil, nil
}

func (s *HostService) validRegion(value any) (string, error) {
	regions := s.server.Config.Regions
	if regions == nil {
		return "", invalidInput("This deployment has no regions configured")
	}
	name, isString := value.(string)
	if _, known := regions.Regions[name]; !isString || !known {
		return "", invalidInput("Region must be one of " + strings.Join(regions.Names, ", "))
	}
	return name, nil
}

// originHost is the host of an origin of this deployment's scheme ("" otherwise).
func (s *HostService) originHost(origin string) string {
	parsed, err := auth.ParseFetchURL(origin)
	if err != nil || parsed.Protocol != s.scheme || urlOrigin(parsed) != origin {
		return ""
	}
	return urlHost(parsed)
}

// candidate is whether an address could belong to an organization, decided without storage.
func (s *HostService) candidate(host string) bool {
	normalized := NormalizeHost(host)
	if normalized == "" || normalized == s.baseHost {
		return false
	}
	if s.server.Config.Hosts.CustomHostnames {
		return true
	}
	for _, pattern := range s.server.Config.Hosts.Patterns {
		if pattern.Regex.MatchString(normalized) {
			return true
		}
	}
	return false
}

// RequestTenant is the organization a request is pinned to, from its address (Host) and, for cross-origin calls,
// its Origin: HOST_MISMATCH when the two name different organizations; WRONG_REGION when another region serves it.
func (s *HostService) RequestTenant(ctx context.Context, request *http.Request) (*HostMatch, error) {
	hosts := s.server.Config.Hosts
	if !hosts.Enabled {
		return nil, nil
	}
	address := ""
	if hosts.ForwardedHost {
		if forwarded, present := headerValue(request.Header, "x-forwarded-host"); present {
			address = core.JSTrim(strings.Split(forwarded, ",")[0])
		}
	}
	if address == "" {
		address = request.URL.Host
		if address == "" {
			address = request.Host
		}
	}
	fromOrigin := ""
	if origin, present := headerValue(request.Header, "origin"); present && origin != "" {
		fromOrigin = s.originHost(origin)
	}
	// Most requests arrive on the deployment's own address: no storage read for those.
	if !s.candidate(address) && !s.candidate(fromOrigin) {
		return nil, nil
	}
	return core.Transact(ctx, s.server.Store, func(ctx context.Context, tx core.IamStore) (*HostMatch, error) {
		var byHost, byOrigin *HostMatch
		var err error
		if address != "" {
			if byHost, err = s.Resolve(ctx, address, tx); err != nil {
				return nil, err
			}
		}
		if fromOrigin != "" && fromOrigin != address {
			if byOrigin, err = s.Resolve(ctx, fromOrigin, tx); err != nil {
				return nil, err
			}
		}
		if byHost != nil && byOrigin != nil && byHost.TenantID != byOrigin.TenantID {
			return nil, core.NewIamError("HOST_MISMATCH", "This page and this address belong to different organizations", 403)
		}
		match := byHost
		if match == nil {
			match = byOrigin
		}
		if match != nil {
			tenant, err := s.server.Tenant(ctx, tx, match.TenantID)
			if err != nil {
				return nil, err
			}
			if err := s.AssertServedHere(ctx, tx, tenant, match.HostRegion); err != nil {
				return nil, err
			}
		}
		return match, nil
	})
}

// TrustsOrigin is true for the origin of an active organization address, so pages served there may call the API.
func (s *HostService) TrustsOrigin(ctx context.Context, origin string) (bool, error) {
	if !s.server.Config.Hosts.Enabled {
		return false, nil
	}
	host := s.originHost(origin)
	if host == "" {
		return false, nil
	}
	match, err := s.Resolve(ctx, host, nil)
	return err == nil && match != nil, nil
}

// RegionForNew is the region a new tenant under parent gets: the requested one (validated; nullish for none), else
// none when inherited ("").
func (s *HostService) RegionForNew(ctx context.Context, tx core.IamStore, parent *core.Object, requested any) (string, error) {
	regions := s.server.Config.Regions
	if nullish(requested) {
		// The first organizations under the (region-less) root are homed where they are created.
		if regions == nil {
			return "", nil
		}
		inherited, err := s.RegionOf(ctx, tx, parent)
		if err != nil || inherited != "" {
			return "", err
		}
		return regions.Current, nil
	}
	region, err := s.validRegion(requested)
	if err != nil {
		return "", err
	}
	if regions.Locate != nil && region != regions.Current {
		return "", invalidInput("Regions keep separate databases here: create the organization on the deployment of its region")
	}
	return region, nil
}

// Region validates a region name for tenants.setRegion and tenants.create.
func (s *HostService) Region(value any) (string, error) { return s.validRegion(value) }

// AssertClaimable refuses with HOSTNAME_NOT_ALLOWED hostnames the deployment itself uses (its base URL and pattern
// space).
func (s *HostService) AssertClaimable(hostname string) error {
	refuse := core.NewIamError("HOSTNAME_NOT_ALLOWED", "This hostname belongs to the deployment itself and cannot be claimed")
	if s.ownHostnames[hostname] {
		return refuse
	}
	for _, pattern := range s.server.Config.Hosts.Patterns {
		if pattern.Regex.MatchString(hostname) {
			return refuse
		}
		if suffix := pattern.Suffix; suffix != "" && (strings.HasSuffix(hostname, suffix) || hostname == suffix[1:]) {
			return refuse
		}
	}
	return nil
}

// Allowed is whether a TLS certificate may be issued for hostname (an on-demand TLS "ask" check).
func (s *HostService) Allowed(ctx context.Context, hostname string) (bool, error) {
	host := NormalizeHost(hostname)
	if host == "" {
		return false, nil
	}
	if s.ownHostnames[trailingPort.ReplaceAllString(host, "")] {
		return true, nil
	}
	match, err := s.Resolve(ctx, host, nil)
	return err == nil && match != nil, nil
}
