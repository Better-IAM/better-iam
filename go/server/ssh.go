package server

// Port of packages/server/src/ssh.ts: the SSH certificate authority. People and machines get short-lived OpenSSH
// user certificates for exactly the hosts and logins policies allow, hosts get certificates their clients trust, and
// hosts refuse revoked certificates through a key revocation list. Each tenant has a user authority and a host
// authority (Ed25519, sealed with the deployment secret). Access is an ordinary policy decision: `ssh:login` on
// `ssh-login/{host}/{login}` (attributes: the host's labels plus `host` and `login`), and `ssh:port-forward` /
// `ssh:agent-forward` / `ssh:x11-forward` on `ssh-host/{host}`. A certificate names each host it opens as the
// principal `{login}@{host}`, and every enrolled host accepts, for each local login, only its own principal, so one
// certificate never opens a host it was not issued for. A certificate lives only as long as the session that
// requested it and the grants that allowed it.

import (
	"context"
	"encoding/base64"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const (
	sshHour = 3_600_000.0
	sshDay  = 86_400_000.0
)

// SshCollections are the collections the module owns (ssh.ts sshCollections).
var SshCollections = []string{"sshSettings", "sshAuthorities", "sshHosts", "sshCertificates"}

// sshForwardingActionNames are the keys of sshForwardingActions, in order.
var sshForwardingActionNames = []string{"ssh:port-forward", "ssh:agent-forward", "ssh:x11-forward"}

// sshBounded is bounded(value, fallback, min, max, name): an integer option within its range, or INVALID_CONFIG.
func sshBounded(value *float64, fallback, min, max float64, name string) (float64, error) {
	resolved := fallback
	if value != nil {
		resolved = *value
	}
	if !core.IsSafeInteger(resolved) || resolved < min || resolved > max {
		return 0, invalidConfig("ssh." + name + " must be an integer between " + jsString(min) + " and " + jsString(max))
	}
	return resolved, nil
}

// ResolveSshOptions (ssh.ts resolveSshOptions) validates the `ssh` option; nil when the module is off. The result
// holds maxUserCertificateMs, hostCertificateMs, clockSkewMs, maxHostsPerCertificate, recordRetentionMs, joinTokenMs
// and issuanceLimit.
func ResolveSshOptions(value *Toggle[SshOptions]) (*core.Object, error) {
	if !value.IsOn() {
		return nil, nil
	}
	options := SshOptions{}
	if value.Options != nil {
		options = *value.Options
	}
	fields := []struct {
		key      string
		value    *float64
		fallback float64
		min, max float64
		name     string
		scale    float64
	}{
		{"maxUserCertificateMs", options.MaxUserCertificateMs, sshDay, 5 * 60_000, 7 * sshDay, "maxUserCertificateMs", 1},
		{"hostCertificateMs", options.HostCertificateMs, 90 * sshDay, sshDay, 365 * sshDay, "hostCertificateMs", 1},
		{"clockSkewMs", options.ClockSkewMs, 5 * 60_000, 0, sshHour, "clockSkewMs", 1},
		{"maxHostsPerCertificate", options.MaxHostsPerCertificate, 64, 1, 256, "maxHostsPerCertificate", 1},
		{"recordRetentionMs", options.RecordRetentionDays, 90, 1, 3650, "recordRetentionDays", sshDay},
		{"joinTokenMs", options.JoinTokenMs, sshDay, 5 * 60_000, 30 * sshDay, "joinTokenMs", 1},
		{"issuanceLimit", options.IssuanceLimit, 60, 1, 100_000, "issuanceLimit", 1},
	}
	resolved := core.NewObject()
	for _, field := range fields {
		number, err := sshBounded(field.value, field.fallback, field.min, field.max, field.name)
		if err != nil {
			return nil, err
		}
		resolved.Set(field.key, number*field.scale)
	}
	return resolved, nil
}

// SshOptionsOf (ssh.ts sshOptions) is the deployment's SSH settings, or nil when `ssh` is off.
func SshOptionsOf(server *ServerContext) (*core.Object, error) {
	if server.Options == nil {
		return nil, nil
	}
	return ResolveSshOptions(server.Options.Ssh)
}

// AssertSsh (ssh.ts assertSsh): the deployment's SSH settings, or FEATURE_DISABLED when the module is off.
func AssertSsh(server *ServerContext) (result *core.Object, err error) {
	options, err := SshOptionsOf(server)
	if err != nil {
		return nil, err
	}
	if options == nil {
		return nil, core.NewIamError("FEATURE_DISABLED", "The SSH certificate authority is not enabled on this deployment", 403)
	}
	return options, nil
}

// SshPlugins (ssh.ts sshPlugins): the catalog entries the module contributes when enabled (the `ssh-login` and
// `ssh-host` types and their actions); none when it is off.
func SshPlugins(options *BetterIamOptions) (result []*core.IamPlugin, err error) {
	resolved, err := ResolveSshOptions(options.Ssh)
	if err != nil || resolved == nil {
		return nil, err
	}
	return []*core.IamPlugin{{
		ID: "better-iam:ssh",
		ResourceTypes: []core.NamedResourceType{
			{Name: SshLoginResourceType, Definition: core.ResourceTypeDefinition{
				Description: "Logging in to an enrolled SSH host as one local account: ssh-login/{host}/{login}",
				Actions:     []string{SshLoginAction},
				Attributes:  []core.NamedAttribute{{Name: "host", Type: "string"}, {Name: "login", Type: "string"}},
			}},
			{Name: SshHostResourceType, Definition: core.ResourceTypeDefinition{
				Description: "An enrolled SSH host, for the forwarding a certificate may allow: ssh-host/{host}",
				Actions:     append([]string(nil), sshForwardingActionNames...),
				Attributes:  []core.NamedAttribute{{Name: "host", Type: "string"}},
			}},
		},
	}}, nil
}

// DefaultSshSettings (ssh.ts defaultSshSettings) is a tenant's settings before anything was changed.
func DefaultSshSettings(tenantID string, options *core.Object) *core.Object {
	maxUser := jsNumber(options.Get("maxUserCertificateMs"))
	return core.NewObject(
		"id", tenantID,
		"tenantId", tenantID,
		"requireMfa", false,
		"requireSecurityKey", false,
		"requireUserVerification", false,
		"bindSourceAddress", false,
		"defaultCertificateMs", math.Min(8*sshHour, maxUser),
		"maxCertificateMs", math.Min(16*sshHour, maxUser),
		"hostPatterns", []any{},
		"revocationVersion", 0.0,
	)
}

// sshKnownHostsMatch is knownHostsMatch: known_hosts pattern-list semantics (case-insensitive): some pattern matches
// and no negated (`!`) one does.
func sshKnownHostsMatch(patterns []string, name string) bool {
	value := core.JSLower(name)
	matched := false
	for _, raw := range patterns {
		pattern := core.JSLower(raw)
		negated := strings.HasPrefix(pattern, "!")
		target := pattern
		if negated {
			target = pattern[1:]
		}
		if !core.MatchPattern(target, value, nil) {
			continue
		}
		if negated {
			return false
		}
		matched = true
	}
	return matched
}

// VerifiedDomains (ssh.ts verifiedDomains): The tenant's verified email/DNS domains (domains API), which bound the
// host names it may vouch for.
func VerifiedDomains(ctx context.Context, tx core.IamStore, tenantID string) (result []string, err error) {
	records, err := tx.Find(ctx, "tenantDomains", core.NewObject("tenantId", tenantID, "status", "verified"), nil)
	if err != nil {
		return nil, err
	}
	result = make([]string, len(records))
	for index, record := range records {
		result[index] = core.JSLower(jsString(record.Get("domain")))
	}
	return result, nil
}

func sshUnderDomain(name string, domains []string) bool {
	for _, domain := range domains {
		if name == domain || strings.HasSuffix(name, "."+domain) {
			return true
		}
	}
	return false
}

var (
	sshUniqueLocal = regexp.MustCompile(`^f[cd][0-9a-f]{0,2}$`)
	sshLinkLocal   = regexp.MustCompile(`^fe[89ab][0-9a-f]?$`)
)

// sshPrivateAddress is privateAddress: private, loopback, link-local and shared address space, never another
// organization's public address.
func sshPrivateAddress(address string) bool {
	switch nodeIsIP(address) {
	case 4:
		parts := strings.Split(address, ".")
		a, b := jsNumber(parts[0]), jsNumber(parts[1])
		return a == 10 ||
			a == 127 ||
			(a == 172 && b >= 16 && b <= 31) ||
			(a == 192 && b == 168) ||
			(a == 169 && b == 254) ||
			(a == 100 && b >= 64 && b <= 127)
	case 6:
		first := strings.Split(core.JSLower(address), ":")[0]
		return address == "::1" || sshUniqueLocal.MatchString(first) || sshLinkLocal.MatchString(first)
	}
	return false
}

var (
	sshPatternItem   = regexp.MustCompile(`^!?[a-zA-Z0-9.*?:_-]{1,253}$`)
	sshIPv4Pattern   = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9.*?]*$`)
	sshIPv6Pattern   = regexp.MustCompile(`^[0-9a-f]{1,4}:[0-9a-f]{1,4}:[0-9a-f:*?]*$`)
	sshIPv6Prefix    = regexp.MustCompile(`^[0-9a-f]{1,4}:[0-9a-f]{1,4}:`)
	sshShortPattern  = regexp.MustCompile(`^[a-z0-9*?-]+$`)
	sshAlphanumeric  = regexp.MustCompile(`[a-z0-9]`)
	sshHostNameShape = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,126}[a-z0-9])?$`)
	sshDigits        = regexp.MustCompile(`^[0-9]+$`)
	sshLabelName     = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,63}$`)
)

// HostPatternList (ssh.ts hostPatternList): Validates `hostPatterns`: every positive pattern must pin a literal
// suffix the organization owns (a verified domain such as `*.corp.example.com`) or a literal address prefix
// (`10.20.*`, `fd00:1:*`); `*` alone is refused.
func HostPatternList(value any, domains []string) (result []string, err error) {
	list, ok := value.([]any)
	if !ok || len(list) > 16 {
		return nil, invalidInput("hostPatterns must list at most 16 known_hosts patterns")
	}
	set := newOrderedSet()
	for _, item := range list {
		text, ok := item.(string)
		if !ok || !sshPatternItem.MatchString(text) {
			return nil, invalidInput("hostPatterns hold known_hosts patterns such as *.corp.example.com")
		}
		set.Add(core.JSLower(text))
	}
	patterns := set.Values()
	var positive []string
	for _, pattern := range patterns {
		if !strings.HasPrefix(pattern, "!") {
			positive = append(positive, pattern)
		}
	}
	if len(patterns) > 0 && len(positive) == 0 {
		return nil, invalidInput("hostPatterns needs at least one pattern that is not negated")
	}
	for _, pattern := range positive {
		wildcard := max(strings.LastIndex(pattern, "*"), strings.LastIndex(pattern, "?"))
		ipv4 := sshIPv4Pattern.MatchString(pattern)
		ipv6 := sshIPv6Pattern.MatchString(pattern)
		suffix := pattern
		if wildcard >= 0 {
			suffix = pattern[wildcard+1:]
		}
		dns := (wildcard < 0 || strings.HasPrefix(suffix, ".")) && sshUnderDomain(strings.TrimPrefix(suffix, "."), domains)
		literalPrivate := wildcard < 0 && nodeIsIP(pattern) > 0 && sshPrivateAddress(pattern)
		// Short (single-label) names such as `web-*` mean nothing outside the organization's network; `*` alone is
		// refused.
		shortName := sshShortPattern.MatchString(pattern) && sshAlphanumeric.MatchString(pattern) && pattern != "localhost"
		if !ipv4 && !ipv6 && !dns && !literalPrivate && !shortName {
			return nil, core.NewIamError("HOST_OUTSIDE_PATTERNS",
				"Pattern "+jsSlice(pattern, 64)+" must end in a verified domain of this organization or fix an address prefix", 400)
		}
	}
	return patterns, nil
}

// AssertVouchable (ssh.ts assertVouchable): Refuses host names or addresses the organization cannot vouch for:
// outside its `hostPatterns` when it has any; otherwise anything but single labels, private addresses, and names
// under its verified domains.
func AssertVouchable(settings *core.Object, domains []string, names []string) (err error) {
	patterns := sshStrings(settings.Get("hostPatterns"))
	// Patterns only narrow: `*` crosses dots, so a pattern alone never makes a foreign name vouchable.
	ipPattern := func(name string) bool {
		for _, pattern := range patterns {
			if !strings.HasPrefix(pattern, "!") &&
				(sshIPv4Pattern.MatchString(pattern) || sshIPv6Prefix.MatchString(pattern)) &&
				core.MatchPattern(pattern, name, nil) {
				return true
			}
		}
		return false
	}
	var outside []string
	for _, name := range names {
		var refused bool
		switch {
		case len(patterns) > 0 && !sshKnownHostsMatch(patterns, name):
			refused = true
		case nodeIsIP(name) != 0:
			refused = !sshPrivateAddress(name) && !ipPattern(name)
		case !strings.Contains(name, "."):
			refused = name == "localhost"
		default:
			refused = !sshUnderDomain(name, domains)
		}
		if refused {
			outside = append(outside, name)
		}
	}
	if len(outside) > 0 {
		shown := outside
		if len(shown) > 5 {
			shown = shown[:5]
		}
		return core.NewIamError("HOST_OUTSIDE_PATTERNS",
			strings.Join(shown, ", ")+" is outside the names this organization can vouch for (verify its domain or set hostPatterns)", 400)
	}
	return nil
}

// AssertNamesFree (ssh.ts assertNamesFree): Refuses names or addresses another host of the tenant already uses (any
// status). hostID "" is none.
func AssertNamesFree(ctx context.Context, tx core.IamStore, tenantID string, names []string, hostID string) (err error) {
	wanted := newOrderedSet(names...)
	hosts, err := tx.Find(ctx, "sshHosts", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return err
	}
	for _, host := range hosts {
		if hostID != "" && host.Get("id") == hostID {
			continue
		}
		candidates := append([]string{jsString(host.Get("name"))}, sshStrings(host.Get("addresses"))...)
		for _, name := range candidates {
			if wanted.Has(name) {
				return core.NewIamError("HOST_NAME_TAKEN", "Host "+jsString(host.Get("name"))+" already uses "+name, 409)
			}
		}
	}
	return nil
}

// AssertHostKeyFree (ssh.ts assertHostKeyFree): Refuses a host key that is a tenant authority key or another host's
// key (a revocation of it would hit them).
func AssertHostKeyFree(ctx context.Context, tx core.IamStore, tenantID string, hostID string, key *core.Object) (err error) {
	if truthy(key.Get("securityKey")) {
		return invalidInput("Host keys cannot be security keys")
	}
	fingerprint := key.Get("fingerprint")
	authorities, err := TenantAuthorities(ctx, tx, tenantID, "")
	if err != nil {
		return err
	}
	for _, authority := range authorities {
		if authority.Get("fingerprint") == fingerprint {
			return invalidInput("An authority key cannot be a host key")
		}
	}
	hosts, err := tx.Find(ctx, "sshHosts", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return err
	}
	for _, host := range hosts {
		if host.Get("id") != hostID && host.Get("hostKeyFingerprint") == fingerprint {
			return core.NewIamError("HOST_KEY_IN_USE", "Host "+jsString(host.Get("name"))+" already uses this key", 409)
		}
	}
	return nil
}

// LoadSshSettings (ssh.ts loadSshSettings): a tenant's settings, with the defaults for anything never stored and the
// lifetimes capped at the deployment's maximum.
func LoadSshSettings(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string) (result *core.Object, err error) {
	options, err := AssertSsh(server)
	if err != nil {
		return nil, err
	}
	stored, err := tx.Get(ctx, "sshSettings", tenantID)
	if err != nil {
		return nil, err
	}
	defaults := DefaultSshSettings(tenantID, options)
	if stored == nil || stored.Get("tenantId") != tenantID {
		return defaults, nil
	}
	// A deployment that lowered its maximum caps what tenants stored earlier.
	maxUser := jsNumber(options.Get("maxUserCertificateMs"))
	storedMax := jsNumber(stored.Get("maxCertificateMs"))
	settings := defaults.Spread(stored)
	settings.Set("maxCertificateMs", math.Min(storedMax, maxUser))
	settings.Set("defaultCertificateMs", math.Min(math.Min(jsNumber(stored.Get("defaultCertificateMs")), storedMax), maxUser))
	return settings, nil
}

// SaveSshSettings (ssh.ts saveSshSettings): Stores a tenant's settings (the record exists once anything was changed
// or revoked).
func SaveSshSettings(ctx context.Context, tx core.IamStore, settings *core.Object) (result *core.Object, err error) {
	existing, err := tx.Get(ctx, "sshSettings", jsString(settings.Get("id")))
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return tx.Put(ctx, "sshSettings", settings)
	}
	return tx.Insert(ctx, "sshSettings", settings)
}

// BumpRevocationVersion (ssh.ts bumpRevocationVersion): Bumps the revocation list version after a revocation.
func BumpRevocationVersion(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string) (err error) {
	settings, err := LoadSshSettings(ctx, server, tx, tenantID)
	if err != nil {
		return err
	}
	_, err = SaveSshSettings(ctx, tx, settings.Spread(core.NewObject("revocationVersion", jsNumber(settings.Get("revocationVersion"))+1)))
	return err
}

// sshAuthorityContext is the sealing context of an authority's key.
func sshAuthorityContext(authority *core.Object) string {
	return "ssh-authority:" + jsString(authority.Get("id"))
}

// TenantAuthorities (ssh.ts tenantAuthorities): a tenant's authorities ("" kind: both), user authorities first, then
// oldest first.
func TenantAuthorities(ctx context.Context, tx core.IamStore, tenantID string, kind string) (result []*core.Object, err error) {
	filter := core.NewObject("tenantId", tenantID)
	if kind != "" {
		filter.Set("kind", kind)
	}
	found, err := tx.Find(ctx, "sshAuthorities", filter, nil)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(found, func(i, j int) bool {
		a, b := found[i], found[j]
		if a.Get("kind") != b.Get("kind") {
			return a.Get("kind") == "user"
		}
		if difference := jsNumber(a.Get("createdAt")) - jsNumber(b.Get("createdAt")); difference != 0 && !math.IsNaN(difference) {
			return difference < 0
		}
		return compareUTF16(jsString(a.Get("id")), jsString(b.Get("id"))) < 0
	})
	return found, nil
}

// CreateAuthority (ssh.ts createAuthority): Creates an authority key, sealed under the deployment secret. status is
// "active" or "pending".
func CreateAuthority(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, kind string, status string, actorID string) (result *core.Object, err error) {
	key, err := GenerateSshAuthorityKey()
	if err != nil {
		return nil, err
	}
	publicBlob := sshBytes(key.Get("publicBlob"))
	publicKey, err := SshKeyLine(publicBlob, "better-iam-"+kind+"-ca")
	if err != nil {
		return nil, err
	}
	now := float64(server.Now())
	record := core.NewObject(
		"id", ID(),
		"tenantId", tenantID,
		"kind", kind,
		"status", status,
		"algorithm", "ssh-ed25519",
		"publicKey", publicKey,
		"fingerprint", sshFingerprint(publicBlob),
		"keySealed", "",
		"createdAt", now,
		"createdBy", actorID,
	)
	if status == "active" {
		record.Set("activatedAt", now)
	}
	record.Set("keySealed", auth.EncryptSecret(jsString(key.Get("privatePkcs8")), server.Options.Secret, sshAuthorityContext(record)))
	return tx.Insert(ctx, "sshAuthorities", record)
}

// EnsureAuthorities (ssh.ts ensureAuthorities): Creates the tenant's user and host authorities when missing; returns
// { user, host, created } (the active ones, and the kinds just created).
func EnsureAuthorities(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, actorID string) (result *core.Object, err error) {
	created := []any{}
	active := func(kind string) (*core.Object, error) {
		authorities, err := TenantAuthorities(ctx, tx, tenantID, kind)
		if err != nil {
			return nil, err
		}
		for _, item := range authorities {
			if item.Get("status") == "active" {
				return item, nil
			}
		}
		created = append(created, kind)
		return CreateAuthority(ctx, server, tx, tenantID, kind, "active", actorID)
	}
	user, err := active("user")
	if err != nil {
		return nil, err
	}
	host, err := active("host")
	if err != nil {
		return nil, err
	}
	return core.NewObject("user", user, "host", host, "created", created), nil
}

// ActiveAuthority (ssh.ts activeAuthority): The active authority of a kind, or SSH_NOT_CONFIGURED.
func ActiveAuthority(ctx context.Context, tx core.IamStore, tenantID string, kind string) (result *core.Object, err error) {
	authorities, err := TenantAuthorities(ctx, tx, tenantID, kind)
	if err != nil {
		return nil, err
	}
	for _, item := range authorities {
		if item.Get("status") == "active" {
			return item, nil
		}
	}
	return nil, core.NewIamError("SSH_NOT_CONFIGURED", "Set up the SSH certificate authority first (ssh.setup)", 409)
}

// sshPublicBlobOf is publicBlobOf: an authority's public key blob, from its key line.
func sshPublicBlobOf(authority *core.Object) []byte {
	parts := strings.Split(jsString(authority.Get("publicKey")), " ")
	if len(parts) < 2 {
		return []byte{}
	}
	return nodeBase64Decode(parts[1])
}

// OpenAuthority (ssh.ts openAuthority): Opens an authority's signing key ({ publicBlob, privateKey }, as
// SshSigningKey returns it).
func OpenAuthority(server *ServerContext, authority *core.Object) (result *core.Object, err error) {
	secrets := append([]string{server.Options.Secret}, server.Options.PreviousSecrets...)
	privatePkcs8, err := auth.DecryptSecret(jsString(authority.Get("keySealed")), secrets, sshAuthorityContext(authority))
	if err != nil {
		return nil, err
	}
	return SshSigningKey(sshPublicBlobOf(authority), privatePkcs8)
}

// SshTrustedStatuses are the authority statuses hosts and clients trust: pending (ahead of a rotation), active, and
// previous (until retired) (ssh.ts trustedStatuses).
var SshTrustedStatuses = newOrderedSet("pending", "active", "previous")

// SshHostName (ssh.ts sshHostName): Host names: lowercase letters, digits, dots and hyphens (no `/`, `@` or
// wildcards, so they can sit in principals).
func SshHostName(value any) (result string, err error) {
	text, ok := value.(string)
	if !ok {
		return "", invalidInput("Invalid host name")
	}
	name := core.JSLower(core.JSTrim(text))
	labels := strings.Split(name, ".")
	if !sshHostNameShape.MatchString(name) ||
		strings.Contains(name, "..") ||
		// A dotted name ending in digits would read as an address (`127.1`).
		(strings.Contains(name, ".") && sshDigits.MatchString(labels[len(labels)-1])) {
		return "", invalidInput(`Host names use 1-128 lowercase letters, digits, "." or "-"`)
	}
	return name, nil
}

var sshReservedLabels = newOrderedSet("host", "login", "tenantId", "name", "status", "id", "type", "ownerId", "parentId", "parentType")

// SshLabels (ssh.ts sshLabels): Host labels: at most 32 `name: value` pairs; the names policies read as
// `resource.{name}`.
func SshLabels(value any) (result *core.Object, err error) {
	if isUndefined(value) {
		return core.NewObject(), nil
	}
	input, ok := value.(*core.Object)
	if !ok {
		return nil, invalidInput("labels must be an object of strings")
	}
	if input.Len() > 32 {
		return nil, invalidInput("A host has at most 32 labels")
	}
	labels := core.NewObject()
	for _, key := range input.Keys() {
		item := input.Get(key)
		if !sshLabelName.MatchString(key) || sshReservedLabels.Has(key) {
			return nil, invalidInput("Invalid or reserved label name " + jsSlice(key, 64))
		}
		text, ok := item.(string)
		if !ok || utf16Len(text) > 256 || hasControl(text) {
			return nil, invalidInput("Label " + key + " must be a string of at most 256 characters")
		}
		labels.Set(key, text)
	}
	return labels, nil
}

// HostByName (ssh.ts hostByName): the tenant's host of that name, or nil.
func HostByName(ctx context.Context, tx core.IamStore, tenantID string, name string) (result *core.Object, err error) {
	found, err := tx.Find(ctx, "sshHosts", core.NewObject("tenantId", tenantID, "uniqueKey", name), nil)
	if err != nil || len(found) == 0 {
		return nil, err
	}
	return found[0], nil
}

// sshHostAttributes is `{ ...host.labels, host: host.name }`.
func sshHostAttributes(host *core.Object) *core.Object {
	labels, _ := host.Get("labels").(*core.Object)
	attributes := core.NewObject().Assign(labels)
	attributes.Set("host", host.Get("name"))
	return attributes
}

// LoginResource (ssh.ts loginResource): What policies see for `ssh-login/{host}/{login}`.
func LoginResource(host *core.Object, login string) (result ResolvedResource, err error) {
	attributes := sshHostAttributes(host)
	attributes.Set("login", login)
	return ResolvedResource{
		TenantID:   jsString(host.Get("tenantId")),
		Type:       SshLoginResourceType,
		ID:         jsString(host.Get("name")) + "/" + login,
		Attributes: attributes,
	}, nil
}

// HostResource (ssh.ts hostResource): What policies see for `ssh-host/{host}`.
func HostResource(host *core.Object) (result ResolvedResource, err error) {
	return ResolvedResource{
		TenantID:   jsString(host.Get("tenantId")),
		Type:       SshHostResourceType,
		ID:         jsString(host.Get("name")),
		Attributes: sshHostAttributes(host),
	}, nil
}

// ResolveSshResource (ssh.ts resolveSshResource): resolves `ssh-login/{host}/{login}` and `ssh-host/{host}` for the
// decision engine (so `authorize`, `whoCan` and `simulate` work on them); nil for other types or when the SSH module
// is off. Unknown hosts and logins are NOT_FOUND.
func ResolveSshResource(ctx context.Context, server *ServerContext, tx core.IamStore, reference core.ResourceRef) (*ResolvedResource, error) {
	if reference.Type != SshLoginResourceType && reference.Type != SshHostResourceType {
		return nil, nil
	}
	options, err := SshOptionsOf(server)
	if err != nil || options == nil {
		return nil, err
	}
	slash := strings.Index(reference.ID, "/")
	name := ""
	if reference.Type == SshHostResourceType {
		name = reference.ID
	} else if slash > 0 {
		name = reference.ID[:slash]
	}
	var host *core.Object
	if name != "" {
		if host, err = HostByName(ctx, tx, reference.TenantID, name); err != nil {
			return nil, err
		}
	}
	if host == nil {
		return nil, core.NewIamError("NOT_FOUND", "Unknown SSH host", 404)
	}
	if reference.Type == SshHostResourceType {
		resource, err := HostResource(host)
		return &resource, err
	}
	login := ""
	if slash > 0 {
		login = reference.ID[slash+1:]
	}
	if !containsString(sshStrings(host.Get("logins")), login) {
		return nil, core.NewIamError("NOT_FOUND", "Unknown login on this host", 404)
	}
	resource, err := LoginResource(host, login)
	return &resource, err
}

// PrincipalFiles (ssh.ts principalFiles): The per-host principals file lines: one file per login holding
// `{login}@{host}`.
func PrincipalFiles(host *core.Object) (result *core.Object, err error) {
	result = core.NewObject()
	name := jsString(host.Get("name"))
	for _, login := range sshStrings(host.Get("logins")) {
		principal, _ := SshLoginPrincipal(login, name)
		result.Set(login, principal+"\n")
	}
	return result, nil
}

// TenantActive (ssh.ts tenantActive): Whether the tenant and every ancestor are active.
func TenantActive(ctx context.Context, server *ServerContext, reader core.IamStore, tenant *core.Object) (result bool, err error) {
	ancestry, err := server.Ancestry(ctx, reader, tenant)
	if err != nil {
		return false, err
	}
	for _, item := range ancestry {
		if item.Get("status") != "active" {
			return false, nil
		}
	}
	return true, nil
}

// sshOrderedLines is a Map<string, string>: insertion order, set keeps a key's place, delete forgets it.
type sshOrderedLines struct {
	keys   *orderedSet
	values map[string]string
}

func (m *sshOrderedLines) set(key, value string) {
	m.keys.Add(key)
	m.values[key] = value
}

func (m *sshOrderedLines) delete(key string) {
	m.keys.Delete(key)
	delete(m.values, key)
}

// sshRevokedHostKeys is revokedHostKeys: host keys clients must refuse, the current key of disabled hosts and the
// keys of unexpired revoked host certificates that no enrolled host uses any more (a rebuilt or deleted host's old
// key). Never an authority key.
func sshRevokedHostKeys(ctx context.Context, server *ServerContext, reader core.IamStore, tenantID string) ([]string, error) {
	now := float64(server.Now())
	hosts, err := reader.Find(ctx, "sshHosts", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	inUse := newOrderedSet()
	for _, host := range hosts {
		if host.Get("status") == "enrolled" && truthy(host.Get("hostKeyFingerprint")) {
			inUse.Add(jsString(host.Get("hostKeyFingerprint")))
		}
	}
	authorities, err := TenantAuthorities(ctx, reader, tenantID, "")
	if err != nil {
		return nil, err
	}
	lines := &sshOrderedLines{keys: newOrderedSet(), values: map[string]string{}}
	for _, host := range hosts {
		if host.Get("status") == "disabled" && truthy(host.Get("hostKey")) && truthy(host.Get("hostKeyFingerprint")) {
			lines.set(jsString(host.Get("hostKeyFingerprint")), jsString(host.Get("hostKey")))
		}
	}
	records, err := sshLiveRecords(ctx, server, reader, tenantID)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		if record.Get("kind") == "host" &&
			!isUndefined(record.Get("revokedAt")) &&
			truthy(record.Get("publicKey")) &&
			jsNumber(record.Get("validBefore")) > now &&
			!inUse.Has(jsString(record.Get("publicKeyFingerprint"))) {
			lines.set(jsString(record.Get("publicKeyFingerprint")), jsString(record.Get("publicKey")))
		}
	}
	for _, authority := range authorities {
		lines.delete(jsString(authority.Get("fingerprint")))
	}
	out := []string{}
	for _, key := range lines.keys.Values() {
		out = append(out, sshKeyHead(lines.values[key]))
	}
	return out, nil
}

// sshKeyHead is `line.split(' ').slice(0, 2).join(' ')`.
func sshKeyHead(line string) string {
	parts := strings.Split(line, " ")
	if len(parts) > 2 {
		parts = parts[:2]
	}
	return strings.Join(parts, " ")
}

// TrustBundle (ssh.ts trustBundle): Trust material. `public` (anyone with the tenant ID): the authority keys, and a
// known_hosts line only for configured `hostPatterns`. `member` (members and hosts): the known_hosts line for the
// enrolled names as well, and `@revoked` lines for host keys clients must refuse.
func TrustBundle(ctx context.Context, server *ServerContext, reader core.IamStore, tenant *core.Object, audience string) (result *core.Object, err error) {
	tenantID := jsString(tenant.Get("id"))
	settings, err := LoadSshSettings(ctx, server, reader, tenantID)
	if err != nil {
		return nil, err
	}
	authorities, err := TenantAuthorities(ctx, reader, tenantID, "")
	if err != nil {
		return nil, err
	}
	trusted := func(kind string) []*core.Object {
		out := []*core.Object{}
		for _, item := range authorities {
			if item.Get("kind") == kind && SshTrustedStatuses.Has(jsString(item.Get("status"))) {
				out = append(out, item)
			}
		}
		return out
	}
	userAuthorities := trusted("user")
	hostAuthorities := trusted("host")
	patterns := sshStrings(settings.Get("hostPatterns"))
	if len(patterns) == 0 && audience == "member" {
		hosts, err := reader.Find(ctx, "sshHosts", core.NewObject("tenantId", tenantID, "status", "enrolled"), nil)
		if err != nil {
			return nil, err
		}
		names := newOrderedSet()
		for _, host := range hosts {
			names.Add(jsString(host.Get("name")))
			for _, address := range sshStrings(host.Get("addresses")) {
				names.Add(address)
			}
		}
		patterns = names.Values()
		sort.SliceStable(patterns, func(i, j int) bool { return compareUTF16(patterns[i], patterns[j]) < 0 })
	}
	comment := "better-iam:" + tenantID
	knownHosts := []string{}
	if len(patterns) > 0 {
		for _, authority := range hostAuthorities {
			knownHosts = append(knownHosts, "@cert-authority "+strings.Join(patterns, ",")+" "+sshKeyHead(jsString(authority.Get("publicKey")))+" "+comment)
		}
	}
	if audience == "member" {
		keys, err := sshRevokedHostKeys(ctx, server, reader, tenantID)
		if err != nil {
			return nil, err
		}
		for _, key := range keys {
			knownHosts = append(knownHosts, "@revoked * "+key+" better-iam:revoked")
		}
	}
	view := func(list []*core.Object) []any {
		out := make([]any, len(list))
		for index, item := range list {
			out[index] = core.NewObject("id", item.Get("id"), "status", item.Get("status"), "publicKey", item.Get("publicKey"),
				"fingerprint", item.Get("fingerprint"))
		}
		return out
	}
	var trustedUserCaKeys, knownHostsText strings.Builder
	for _, item := range userAuthorities {
		trustedUserCaKeys.WriteString(jsString(item.Get("publicKey")) + "\n")
	}
	for _, line := range knownHosts {
		knownHostsText.WriteString(line + "\n")
	}
	return core.NewObject(
		"tenantId", tenantID,
		// For hosts: sshd `TrustedUserCAKeys`.
		"userAuthorities", view(userAuthorities),
		// For clients: known_hosts `@cert-authority` lines.
		"hostAuthorities", view(hostAuthorities),
		"hostPatterns", settings.Get("hostPatterns"),
		"trustedUserCaKeys", trustedUserCaKeys.String(),
		"knownHosts", knownHostsText.String(),
	), nil
}

// sshLiveRecords is liveRecords: unexpired certificate records of a tenant (plus some recently expired ones), read
// through the expiry index: `expiresAt` is `validBefore` plus a retention of at least a day, so a record still valid
// has `expiresAt` over a day ahead.
func sshLiveRecords(ctx context.Context, server *ServerContext, reader core.IamStore, tenantID string) ([]*core.Object, error) {
	now := float64(server.Now())
	from := now + sshDay
	records, err := core.FindOrdered(ctx, reader, "sshCertificates", core.NewObject("tenantId", tenantID),
		core.OrderOptions{Field: "expiresAt", From: &from}, nil)
	if err != nil {
		return nil, err
	}
	out := make([]*core.Object, 0, len(records))
	for _, record := range records {
		if jsNumber(record.Get("validBefore")) > now {
			out = append(out, record)
		}
	}
	return out, nil
}

// LiveCertificates (ssh.ts liveCertificates): Certificate records that are still valid and not revoked. filter
// holds tenantId and any other members to match.
func LiveCertificates(ctx context.Context, server *ServerContext, tx core.IamStore, filter *core.Object) (result []*core.Object, err error) {
	now := float64(server.Now())
	records, err := tx.Find(ctx, "sshCertificates", filter.Spread(core.NewObject("revokedAt", core.Undefined)), nil)
	if err != nil {
		return nil, err
	}
	result = make([]*core.Object, 0, len(records))
	for _, record := range records {
		if jsNumber(record.Get("validBefore")) > now {
			result = append(result, record)
		}
	}
	return result, nil
}

// MarkRevoked (ssh.ts markRevoked): Marks one certificate revoked (idempotent); the caller bumps the revocation
// version.
func MarkRevoked(ctx context.Context, server *ServerContext, tx core.IamStore, record *core.Object, reason string, actorID string) (result *core.Object, err error) {
	if !isUndefined(record.Get("revokedAt")) {
		return record, nil
	}
	return tx.Put(ctx, "sshCertificates", record.Spread(core.NewObject(
		"revokedAt", float64(server.Now()),
		"revokedBy", actorID,
		"revocationReason", reason,
	)))
}

// sshActiveIdentity is activeIdentity: an identity that exists, is active, and has not expired.
func sshActiveIdentity(server *ServerContext, identity *core.Object) bool {
	return identity != nil && identity.Get("status") == "active" && !server.IdentityExpired(identity)
}

// RevocationList (ssh.ts revocationList): A tenant's binary key revocation list ("" kind: user).
//   - `user` (sshd `RevokedKeys`): the serials of unexpired user certificates that were revoked, whose holder is no
//     longer active or whose session is gone (even before the sweep marks them), or all of them while the tenant or
//     an ancestor is suspended.
//   - `host` (ssh `RevokedHostKeys` on clients): revoked host certificate serials and host keys clients must refuse.
func RevocationList(ctx context.Context, server *ServerContext, reader core.IamStore, tenant *core.Object, kind string) (result *core.Object, err error) {
	if kind == "" {
		kind = "user"
	}
	tenantID := jsString(tenant.Get("id"))
	settings, err := LoadSshSettings(ctx, server, reader, tenantID)
	if err != nil {
		return nil, err
	}
	now := float64(server.Now())
	active, err := TenantActive(ctx, server, reader, tenant)
	if err != nil {
		return nil, err
	}
	live, err := sshLiveRecords(ctx, server, reader, tenantID)
	if err != nil {
		return nil, err
	}
	identities := map[string]bool{}
	authorityOrder := newOrderedSet()
	bySerial := map[string][]any{}
	revoked := 0
	for _, record := range live {
		if record.Get("kind") != kind {
			continue
		}
		dead := !isUndefined(record.Get("revokedAt")) || (kind == "user" && !active)
		if identityID := record.Get("identityId"); !dead && truthy(identityID) {
			key := jsString(identityID)
			if _, known := identities[key]; !known {
				identity, err := reader.Get(ctx, "identities", key)
				if err != nil {
					return nil, err
				}
				identities[key] = sshActiveIdentity(server, identity)
			}
			dead = !identities[key]
		}
		if sessionID := record.Get("sessionId"); !dead && truthy(sessionID) {
			session, err := reader.Get(ctx, "sessions", jsString(sessionID))
			if err != nil {
				return nil, err
			}
			dead = session == nil || jsNumber(session.Get("expiresAt")) <= now || session.Get("identityId") != record.Get("identityId")
		}
		if !dead {
			continue
		}
		revoked++
		serial, err := sshBigUint(jsString(record.Get("serial")))
		if err != nil {
			return nil, err
		}
		authorityID := jsString(record.Get("authorityId"))
		authorityOrder.Add(authorityID)
		bySerial[authorityID] = append(bySerial[authorityID], serial)
	}
	authorityList, err := TenantAuthorities(ctx, reader, tenantID, "")
	if err != nil {
		return nil, err
	}
	authorities := map[string]*core.Object{}
	for _, item := range authorityList {
		authorities[jsString(item.Get("id"))] = item
	}
	keys := []any{}
	if kind == "host" {
		lines, err := sshRevokedHostKeys(ctx, server, reader, tenantID)
		if err != nil {
			return nil, err
		}
		for _, line := range lines {
			parts := strings.Split(line, " ")
			data := ""
			if len(parts) > 1 {
				data = parts[1]
			}
			keys = append(keys, nodeBase64Decode(data))
		}
	}
	sections := []any{}
	for _, authorityID := range authorityOrder.Values() {
		if authority := authorities[authorityID]; authority != nil {
			sections = append(sections, sshRaw("authority", sshPublicBlobOf(authority), "serials", bySerial[authorityID]))
		}
	}
	version, err := sshBigUint(jsNumber(settings.Get("revocationVersion")))
	if err != nil {
		return nil, err
	}
	krl, err := BuildSshKrl(sshRaw(
		"version", version,
		"generatedAt", now,
		"comment", "better-iam:"+tenantID+":"+kind,
		"authorities", sections,
		"keys", keys,
	))
	if err != nil {
		return nil, err
	}
	return core.NewObject(
		"tenantId", tenantID,
		"kind", kind,
		"version", settings.Get("revocationVersion"),
		"generatedAt", now,
		"tenantActive", active,
		"revokedCertificates", float64(revoked),
		"revokedHostKeys", float64(len(keys)),
		// The KRL, base64: write it (decoded) to the file sshd's `RevokedKeys` (or ssh's `RevokedHostKeys`) names.
		"krl", base64.StdEncoding.EncodeToString(krl),
	), nil
}

// SshGrantDeadline (ssh.ts grantDeadline): The latest a certificate may be valid until given the caller's
// time-limited grants of `ssh:login` (grant_deadline.go).
func SshGrantDeadline(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID string, horizon float64) (float64, error) {
	return GrantDeadline(ctx, server, tx, principal, tenantID, horizon, SshLoginAction)
}

// sshSweepState is a session's prepared decision in the sweep: the decision, or ended / skip.
type sshSweepState struct {
	prepared *PreparedDecision
	ended    bool
	skip     bool
}

// SweepSshCertificates (ssh.ts sweepSshCertificates): Continuous authorization for certificates already issued:
// revokes live user certificates whose holder is no longer active, whose issuing session (user session, API key,
// role session, session token or delegated session) was revoked, ended or no longer validates, or whose hosts,
// logins and forwarding policies no longer allow as decided for that very session. A scheduler job
// (`iam.ssh.sweep`); hosts pick the result up with their next revocation list. input may hold tenantId (nil: every
// tenant with live user certificates). The result is { examined, revoked, byReason }.
func SweepSshCertificates(ctx context.Context, server *ServerContext, input *core.Object) (result *core.Object, err error) {
	if _, err := AssertSsh(server); err != nil {
		return nil, err
	}
	examined, revokedCount := 0, 0
	byReason := core.NewObject()
	var tenantIDs []string
	if tenantID := member(input, "tenantId"); truthy(tenantID) {
		tenantIDs = []string{jsString(tenantID)}
	} else {
		records, err := server.Store.Find(ctx, "sshCertificates", core.NewObject("kind", "user", "revokedAt", core.Undefined), nil)
		if err != nil {
			return nil, err
		}
		set := newOrderedSet()
		for _, record := range records {
			if jsNumber(record.Get("validBefore")) > float64(server.Now()) {
				set.Add(jsString(record.Get("tenantId")))
			}
		}
		tenantIDs = set.Values()
	}
	for _, tenantID := range tenantIDs {
		err := server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
			tenant, err := tx.Get(ctx, "tenants", tenantID)
			if err != nil || tenant == nil {
				return err
			}
			records, err := LiveCertificates(ctx, server, tx, core.NewObject("tenantId", tenantID, "kind", "user"))
			if err != nil {
				return err
			}
			hostList, err := tx.Find(ctx, "sshHosts", core.NewObject("tenantId", tenantID), nil)
			if err != nil {
				return err
			}
			hostNames := newOrderedSet()
			hosts := map[string]*core.Object{}
			for _, host := range hostList {
				name := jsString(host.Get("name"))
				hostNames.Add(name)
				hosts[name] = host
			}
			// With security clearances, the hosts' resources carry their classification labels, as `resolve`
			// attaches them.
			resources := []ResolvedResource{}
			if len(records) > 0 {
				for _, name := range hostNames.Values() {
					host := hosts[name]
					resource, _ := HostResource(host)
					resources = append(resources, resource)
					for _, login := range sshStrings(host.Get("logins")) {
						resource, _ := LoginResource(host, login)
						resources = append(resources, resource)
					}
				}
			}
			labeled, err := ModuleResourceLabels(ctx, server, tx, tenantID, resources)
			if err != nil {
				return err
			}
			// Per issuing session: its decision, `ended` when it no longer validates, `skip` while its tenant is
			// suspended.
			decisions := map[string]sshSweepState{}
			changed := false
			for _, record := range records {
				examined++
				var identity *core.Object
				if identityID := record.Get("identityId"); truthy(identityID) {
					if identity, err = tx.Get(ctx, "identities", jsString(identityID)); err != nil {
						return err
					}
				}
				reason := ""
				if !sshActiveIdentity(server, identity) {
					reason = "identity-inactive"
				} else {
					sessionID, deviceKeyID := record.Get("sessionId"), record.Get("deviceKeyId")
					key := jsString(coalesce(sessionID, "")) + " " + jsString(coalesce(deviceKeyID, ""))
					if _, known := decisions[key]; !known {
						state, err := sshSweepDecision(ctx, server, tx, tenant, tenantID, identity, sessionID, deviceKeyID)
						if err != nil {
							return err
						}
						decisions[key] = state
					}
					state := decisions[key]
					if state.skip {
						continue
					}
					if state.ended {
						reason = "session-ended"
					} else {
						lost, err := sshAccessLost(state.prepared, labeled, record, hosts)
						if err != nil {
							return err
						}
						if lost {
							reason = "access-changed"
						}
					}
				}
				if reason == "" {
					continue
				}
				if _, err := MarkRevoked(ctx, server, tx, record, reason, "deployment-operator"); err != nil {
					return err
				}
				identityID := record.Get("identityId")
				if nullish(identityID) {
					identityID = nil
				}
				err = server.Events.RecordAudit(ctx, tx, core.NewObject(
					"id", ID(),
					"tenantId", tenantID,
					"actorId", "deployment-operator",
					"action", "ssh:certificate:revoke",
					"resourceId", "ssh/certificates/"+jsString(record.Get("id")),
					"outcome", "allow",
					"timestamp", float64(server.Now()),
					"metadata", core.NewObject("reason", reason, "serial", record.Get("serial"), "identityId", identityID),
				))
				if err != nil {
					return err
				}
				revokedCount++
				byReason.Set(reason, jsNumber(coalesce(byReason.Get(reason), 0.0))+1)
				changed = true
			}
			if changed {
				return BumpRevocationVersion(ctx, server, tx, tenantID)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return core.NewObject("examined", float64(examined), "revoked", float64(revokedCount), "byReason", byReason), nil
}

// sshSweepDecision prepares the `ssh:login` decision of one issuing session (and the device key its request proved),
// validated the way every request is: `ended` when it no longer validates, `skip` while its tenant is suspended.
func sshSweepDecision(ctx context.Context, server *ServerContext, tx core.IamStore, tenant *core.Object, tenantID string, identity *core.Object, sessionID, deviceKeyID any) (sshSweepState, error) {
	var session *core.Object
	if truthy(sessionID) {
		var err error
		if session, err = tx.Get(ctx, "sessions", jsString(sessionID)); err != nil {
			return sshSweepState{}, err
		}
	}
	if session == nil || session.Get("identityId") != identity.Get("id") {
		return sshSweepState{ended: true}, nil
	}
	prepared, err := func() (*PreparedDecision, error) {
		// The same validation every request gets: revocations, expiry and idle limits, authority chains, delegations
		// and their confirmations, network rules.
		current, err := server.Principals.CurrentPrincipal(ctx, tx, &Principal{Identity: identity, Session: session})
		if err != nil {
			return nil, err
		}
		// With no request to carry a proof, device conditions judge the device the issuing request proved.
		principal := current
		if truthy(deviceKeyID) {
			if principal, err = WithDeviceKey(current, jsString(deviceKeyID)); err != nil {
				return nil, err
			}
		}
		prepared, err := server.Decisions.PrepareDecision(ctx, tx, principal, tenant, SshLoginAction)
		if err != nil {
			return nil, err
		}
		if IsRootOverride(prepared) && principal.Identity.Get("tenantId") != tenantID {
			prepared = &PreparedDecision{Fixed: &core.Decision{Allowed: false, Reason: "ROOT_SSH_RESTRICTED", Matched: []string{}}}
		}
		return prepared, nil
	}()
	if err != nil {
		known, isIam := asIamError(err)
		// A module that is not ported yet is not a session that ended.
		if isIam && known.Code == "NOT_IMPLEMENTED" {
			return sshSweepState{}, err
		}
		// A suspended tenant is refused by the revocation list itself; its certificates return with it.
		if isIam && known.Code == "TENANT_INACTIVE" {
			return sshSweepState{skip: true}, nil
		}
		return sshSweepState{ended: true}, nil
	}
	return sshSweepState{prepared: prepared}, nil
}

// sshAccessLost reports whether a certificate's logins or forwarding are no longer allowed for its session.
func sshAccessLost(prepared *PreparedDecision, labeled func(ResolvedResource) ResolvedResource, record *core.Object, hosts map[string]*core.Object) (bool, error) {
	decide := func(resource ResolvedResource, action string) (bool, error) {
		decision, err := DecideOn(prepared, labeled(resource), action)
		return decision.Allowed, err
	}
	access, _ := record.Get("access").([]any)
	var named []*core.Object
	for _, item := range access {
		if host := hosts[jsString(member(item, "host"))]; host != nil {
			named = append(named, host)
		}
	}
	loginLost := false
	for _, item := range access {
		host := hosts[jsString(member(item, "host"))]
		// A deleted host takes nothing away; its principals open nothing any more.
		if host == nil {
			continue
		}
		hostLogins := sshStrings(host.Get("logins"))
		for _, login := range sshStrings(member(item, "logins")) {
			if !containsString(hostLogins, login) {
				loginLost = true
				break
			}
			resource, _ := LoginResource(host, login)
			allowed, err := decide(resource, SshLoginAction)
			if err != nil {
				return false, err
			}
			if !allowed {
				loginLost = true
				break
			}
		}
		if loginLost {
			break
		}
	}
	extensions := sshStrings(record.Get("extensions"))
	forwardingLost := false
	for _, action := range sshForwardingActionNames {
		if !containsString(extensions, jsString(SshForwardingActions.Get(action))) {
			continue
		}
		for _, host := range named {
			resource, _ := HostResource(host)
			allowed, err := decide(resource, action)
			if err != nil {
				return false, err
			}
			if !allowed {
				forwardingLost = true
				break
			}
		}
		if forwardingLost {
			break
		}
	}
	return loginLost || forwardingLost, nil
}

// CertificateKeyID (ssh.ts certificateKeyId): A key ID for sshd logs: who (and the agent acting for them), printable
// ASCII only.
func CertificateKeyID(principal *Principal) (result string, err error) {
	identity, session := principal.Identity, principal.Session
	who := identity.Get("email")
	if nullish(who) {
		who = identity.Get("name")
	}
	if nullish(who) {
		who = identity.Get("id")
	}
	via := ""
	if agent, ok := session.Get("agentId").(string); ok {
		via = " via agent " + agent
	} else if original := session.Get("originalIdentityId"); truthy(original) {
		via = " via " + jsString(original)
	}
	text := jsString(who) + " (" + jsString(identity.Get("id")) + ")" + via
	units := core.ToUTF16(text)
	for index, unit := range units {
		if unit < 0x20 || unit > 0x7e || unit == '"' {
			units[index] = '_'
		}
	}
	if len(units) > 256 {
		units = units[:256]
	}
	return core.FromUTF16(units), nil
}

// StoredHostKey (ssh.ts storedHostKey): Parses a stored host key line (enrolled keys were validated when they
// arrived).
func StoredHostKey(host *core.Object) (result *core.Object, err error) {
	return ParseSshPublicKey(host.Get("hostKey"), nil)
}

// DelegatedCertificateMs is ssh.ts DELEGATED_CERTIFICATE_MS: certificates for agents acting for people (delegated
// sessions) are short, as their confirmations are.
const DelegatedCertificateMs = 600000

// SshForwardingActions is ssh.ts sshForwardingActions: forwarding a certificate allows only when every host it names
// allows it (certificate extensions are global).
var SshForwardingActions = mustObject(`{"ssh:port-forward":"permit-port-forwarding","ssh:agent-forward":"permit-agent-forwarding","ssh:x11-forward":"permit-X11-forwarding"}`)

// SshLoginAction is ssh.ts sshLoginAction.
const SshLoginAction = "ssh:login"

// SshLoginResourceType and SshHostResourceType are the SSH resource types (ssh.ts).
const (
	SshLoginResourceType = "ssh-login"
	SshHostResourceType  = "ssh-host"
)
