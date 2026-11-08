package server

// Port of packages/server/src/api/ssh.ts: the `ssh` API group, the tenant's SSH certificate authority.
// Administrators (`iam:ssh:manage`, `iam:ssh:read`) set it up, enroll hosts and review and revoke certificates;
// members get certificates for what policies allow them (`ssh:login` on `ssh-login/{host}/{login}`); hosts enroll
// with a one-time join token and then check in with their renewal token (`syncHost`), which also renews their
// certificate and hands them the current trust and revocation list.

import (
	"context"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// sshHostKeyFile names the host key file of each host key type (the host certificate sits next to it).
var sshHostKeyFile = map[string]string{
	"ssh-ed25519":         "ssh_host_ed25519_key",
	"ecdsa-sha2-nistp256": "ssh_host_ecdsa_key",
	"ecdsa-sha2-nistp384": "ssh_host_ecdsa_key",
	"ecdsa-sha2-nistp521": "ssh_host_ecdsa_key",
	"ssh-rsa":             "ssh_host_rsa_key",
}

const sshPrincipalsDirectory = "/etc/ssh/better-iam/principals"

// sshForcedRenewalMs: a forced renewal (`renew: true`) is honoured at most this often.
const sshForcedRenewalMs = 3_600_000.0

// sshRevocationCacheMs is how long a served revocation list is reused for the same version.
const sshRevocationCacheMs = 10_000.0

// sshAuditedRefusals are the codes a host-management refusal is audited with (a denied `iam:ssh:manage`).
var sshAuditedRefusals = newOrderedSet("HOST_OUTSIDE_PATTERNS", "HOST_NAME_TAKEN", "HOST_KEY_IN_USE")

// sshPublicAuthority is an authority as administrators see it: never the sealed key.
func sshPublicAuthority(authority *core.Object) *core.Object {
	view := core.NewObject(
		"id", authority.Get("id"),
		"tenantId", authority.Get("tenantId"),
		"kind", authority.Get("kind"),
		"status", authority.Get("status"),
		"algorithm", authority.Get("algorithm"),
		"publicKey", authority.Get("publicKey"),
		"fingerprint", authority.Get("fingerprint"),
		"createdAt", authority.Get("createdAt"),
		"createdBy", authority.Get("createdBy"),
	)
	for _, key := range []string{"activatedAt", "rotatedAt", "retiredAt"} {
		if value := authority.Get(key); !isUndefined(value) {
			view.Set(key, value)
		}
	}
	return view
}

// sshPublicAuthorities maps sshPublicAuthority over a list.
func sshPublicAuthorities(authorities []*core.Object) []any {
	out := make([]any, len(authorities))
	for index, authority := range authorities {
		out[index] = sshPublicAuthority(authority)
	}
	return out
}

// sshPublicHost is a host as administrators see it: never its token hashes.
func sshPublicHost(host *core.Object) *core.Object {
	view := host.Spread()
	for _, key := range []string{"joinTokenHash", "renewalTokenHash", "previousRenewalTokenHash", "uniqueKey"} {
		view.Delete(key)
	}
	return view
}

// sshSettingsView is the tenant's settings with the deployment's ceiling for maxCertificateMs.
func sshSettingsView(settings *core.Object, options *core.Object) *core.Object {
	view := core.NewObject(
		"tenantId", settings.Get("tenantId"),
		"requireMfa", settings.Get("requireMfa"),
		"requireSecurityKey", settings.Get("requireSecurityKey"),
		"requireUserVerification", settings.Get("requireUserVerification"),
		"bindSourceAddress", settings.Get("bindSourceAddress"),
		"defaultCertificateMs", settings.Get("defaultCertificateMs"),
		"maxCertificateMs", settings.Get("maxCertificateMs"),
		"hostPatterns", settings.Get("hostPatterns"),
		"revocationVersion", settings.Get("revocationVersion"),
		"deploymentMaxCertificateMs", options.Get("maxUserCertificateMs"),
	)
	for _, key := range []string{"updatedAt", "updatedBy"} {
		if value := settings.Get(key); !isUndefined(value) {
			view.Set(key, value)
		}
	}
	return view
}

// sshListOf is listOf: a list of at most max items, each validated, without duplicates (first occurrence kept).
func sshListOf(value any, name string, max int, each func(item any) (string, error)) ([]string, error) {
	list, ok := value.([]any)
	if !ok || len(list) > max {
		return nil, invalidInput(name + " must be a list of at most " + strconv.Itoa(max) + " items")
	}
	mapped := make([]string, len(list))
	for index, item := range list {
		text, err := each(item)
		if err != nil {
			return nil, err
		}
		mapped[index] = text
	}
	return newOrderedSet(mapped...).Values(), nil
}

// sshHostLogins validates a host's logins: at least one.
func sshHostLogins(value any) ([]string, error) {
	logins, err := sshListOf(value, "logins", 64, SshLogin)
	if err != nil {
		return nil, err
	}
	if len(logins) == 0 {
		return nil, invalidInput("A host needs at least one login")
	}
	return logins, nil
}

// sshHostAddresses validates a host's addresses (none when undefined).
func sshHostAddresses(value any) ([]string, error) {
	if isUndefined(value) {
		return []string{}, nil
	}
	return sshListOf(value, "addresses", 32, SshHostAddress)
}

// sshWithout is `list.filter((item) => item !== name)`.
func sshWithout(list []string, name string) []string {
	out := []string{}
	for _, item := range list {
		if item != name {
			out = append(out, item)
		}
	}
	return out
}

// sshMissing is `list.filter((item) => !other.includes(item))`.
func sshMissing(list, other []string) []string {
	out := []string{}
	for _, item := range list {
		if !containsString(other, item) {
			out = append(out, item)
		}
	}
	return out
}

func sshInvalidToken() *core.IamError {
	return core.NewIamError("INVALID_TOKEN", "Invalid or expired host token", 401)
}

// sshTokenHost reads the host a join or renewal token names: `biam_sshj.{hostId}.{secret}` /
// `biam_sshr.{hostId}.{secret}`.
func sshTokenHost(value any, prefix string) (string, error) {
	var parts []string
	if text, ok := value.(string); ok && utf16Len(text) <= 256 {
		parts = strings.Split(text, ".")
	}
	if len(parts) != 3 || parts[0] != prefix || parts[1] == "" || parts[2] == "" {
		return "", sshInvalidToken()
	}
	return parts[1], nil
}

// sshCertificateView is a certificate record as callers see it: no line, public key, session or retention, plus its
// status.
func sshCertificateView(record *core.Object, now float64) *core.Object {
	view := record.Spread()
	for _, key := range []string{"expiresAt", "uniqueKey", "certificate", "publicKey", "sessionId"} {
		view.Delete(key)
	}
	status := "active"
	if !isUndefined(record.Get("revokedAt")) {
		status = "revoked"
	} else if jsNumber(record.Get("validBefore")) <= now {
		status = "expired"
	}
	view.Set("status", status)
	return view
}

// sshSameList is `JSON.stringify(a) === JSON.stringify(b)` for two lists.
func sshSameList(a, b any) bool {
	left, _, _ := core.Stringify(a)
	right, _, _ := core.Stringify(b)
	return left == right
}

// sshByName sorts hosts by name (`a.name < b.name ? -1 : 1`).
func sshByName(hosts []*core.Object) []*core.Object {
	sorted := append([]*core.Object(nil), hosts...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return compareUTF16(jsString(sorted[i].Get("name")), jsString(sorted[j].Get("name"))) < 0
	})
	return sorted
}

// sshNewestFirst sorts certificate records or views `b.issuedAt - a.issuedAt || (a.id < b.id ? -1 : 1)`.
func sshNewestFirst(records []*core.Object) {
	sort.SliceStable(records, func(i, j int) bool {
		a, b := records[i], records[j]
		if difference := jsNumber(b.Get("issuedAt")) - jsNumber(a.Get("issuedAt")); difference != 0 && !math.IsNaN(difference) {
			return difference < 0
		}
		return compareUTF16(jsString(a.Get("id")), jsString(b.Get("id"))) < 0
	})
}

// sshPrintable is `text.replace(/[^\x20-\x7e]/g, '_')` (per UTF-16 unit).
func sshPrintable(text string) string {
	units := core.ToUTF16(text)
	for index, unit := range units {
		if unit < 0x20 || unit > 0x7e {
			units[index] = '_'
		}
	}
	return core.FromUTF16(units)
}

// sshAccess is one host a principal may open: the logins and the forwarding each action allows.
type sshAccess struct {
	host       *core.Object
	logins     []string
	forwarding map[string]bool
}

// sshRevocationEntry is a cached revocation list.
type sshRevocationEntry struct {
	at      float64
	version float64
	value   *core.Object
}

// SshAPI is the `ssh` API group (packages/server/src/api/ssh.ts createSshApi): every method runs through the
// operation envelope; the router maps POST {basePath}/ssh/{method} onto it.
type SshAPI struct {
	server *ServerContext
	// The public revocation list is read by every host every few minutes: cached per tenant, kind and version and
	// read outside any transaction (a revocation bumps the version, so it is never served stale; holders or sessions
	// that ended meanwhile show within seconds).
	mu         sync.Mutex
	cache      map[string]sshRevocationEntry
	cacheOrder []string
}

// CreateSshAPI builds the `ssh` API group.
func CreateSshAPI(server *ServerContext) *SshAPI {
	return &SshAPI{server: server, cache: map[string]sshRevocationEntry{}}
}

const (
	sshManage = "iam:ssh:manage"
	sshRead   = "iam:ssh:read"
)

func sshTenantOf(value any) (string, error) { return Text(value, "tenantId") }

func (api *SshAPI) activeTenant(ctx context.Context, tx core.IamStore, tenantID string) (*core.Object, error) {
	tenant, err := api.server.Tenant(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	active, err := TenantActive(ctx, api.server, tx, tenant)
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, core.NewIamError("TENANT_INACTIVE", "This organization is not active", 403)
	}
	return tenant, nil
}

func (api *SshAPI) scopedHost(ctx context.Context, tx core.IamStore, tenantID string, hostID any) (*core.Object, error) {
	id, err := Text(hostID, "hostId")
	if err != nil {
		return nil, err
	}
	return api.server.Scoped(ctx, tx, "sshHosts", id, tenantID)
}

func (api *SshAPI) hostRecordName(ctx context.Context, tenantID string, hostID any) (string, error) {
	host, err := api.scopedHost(ctx, api.server.Store, tenantID, hostID)
	if err != nil {
		return "", err
	}
	return jsString(host.Get("name")), nil
}

func sshJoinToken(hostID string) string    { return "biam_sshj." + hostID + "." + Token() }
func sshRenewalToken(hostID string) string { return "biam_sshr." + hostID + "." + Token() }

// refuseHost records a refused host call (bad token, key swap) in its own transaction, then returns the refusal.
func (api *SshAPI) refuseHost(ctx context.Context, host *core.Object, action string, refusal *core.IamError, metadata *core.Object) error {
	if host != nil {
		server := api.server
		details := core.NewObject("reason", refusal.Code)
		if metadata != nil {
			details.Assign(metadata)
		}
		// Bookkeeping never masks the refusal.
		_ = server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
			return server.Events.RecordAudit(ctx, tx, core.NewObject(
				"id", ID(),
				"tenantId", host.Get("tenantId"),
				"actorId", "ssh-host:"+jsString(host.Get("id")),
				"action", action,
				"resourceId", "ssh/hosts/"+jsString(host.Get("name")),
				"outcome", "deny",
				"timestamp", float64(server.Now()),
				"metadata", details,
			))
		})
	}
	return refusal
}

// audited runs an administrative host operation whose policy-shaped refusals (names outside patterns, taken) are
// audited.
func sshAudited[T any](ctx context.Context, api *SshAPI, credential core.CredentialInput, tenantID, resourceID string, run func() (T, error)) (T, error) {
	value, err := run()
	if err == nil {
		return value, nil
	}
	var known *core.IamError
	if errors.As(err, &known) && sshAuditedRefusals.Has(known.Code) {
		server := api.server
		// Bookkeeping never masks the refusal.
		if principal, authErr := server.Principals.Authenticate(ctx, credential); authErr == nil {
			_ = server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
				return server.Events.Audit(ctx, tx, principal, sshManage, tenantID, resourceID, "deny", false, core.NewObject(
					"reason", known.Code,
					"message", jsSlice(known.Message, 256),
				))
			})
		}
	}
	return value, err
}

// assertNamesAllowed: every name a host certificate would carry must be one the organization can vouch for, used by
// no other host, and within the caller's own `iam:ssh:manage` scope (`iam/ssh/hosts/{name}` for each address), so an
// administrator of some hosts cannot claim another host's name. hostID "" is none.
func (api *SshAPI) assertNamesAllowed(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string, names []string, hostID string) error {
	server := api.server
	settings, err := LoadSshSettings(ctx, server, tx, tenantID)
	if err != nil {
		return err
	}
	domains, err := VerifiedDomains(ctx, tx, tenantID)
	if err != nil {
		return err
	}
	if err := AssertVouchable(settings, domains, names); err != nil {
		return err
	}
	if err := AssertNamesFree(ctx, tx, tenantID, names, hostID); err != nil {
		return err
	}
	for _, name := range names[1:] {
		decision, err := server.Operations.RecordedDecision(ctx, tx, principal, AuthorizationRequest{
			TenantID: tenantID,
			Action:   sshManage,
			Resource: ResourceTarget{Type: "iam", ID: "ssh/hosts/" + name},
		})
		if err != nil {
			return err
		}
		if !decision.Allowed {
			return NewOperationDenied("You may not manage the host name " + name)
		}
	}
	return nil
}

// certifyHost issues a host certificate for the host's name and addresses and supersedes every earlier one. It
// returns the record and the certificate line.
func (api *SshAPI) certifyHost(ctx context.Context, tx core.IamStore, host *core.Object, key *core.Object, options *core.Object) (*core.Object, string, error) {
	server := api.server
	tenantID := jsString(host.Get("tenantId"))
	hostID := jsString(host.Get("id"))
	name := jsString(host.Get("name"))
	authority, err := ActiveAuthority(ctx, tx, tenantID, "host")
	if err != nil {
		return nil, "", err
	}
	now := float64(server.Now())
	serialValue, err := SshSerial()
	if err != nil {
		return nil, "", err
	}
	serial := serialValue.(uint64)
	principals := newOrderedSet(append([]string{name}, sshStrings(host.Get("addresses"))...)...).Values()
	// Never vouch for a name outside the organization's reach, whatever the host record says.
	settings, err := LoadSshSettings(ctx, server, tx, tenantID)
	if err != nil {
		return nil, "", err
	}
	domains, err := VerifiedDomains(ctx, tx, tenantID)
	if err != nil {
		return nil, "", err
	}
	if err := AssertVouchable(settings, domains, principals); err != nil {
		return nil, "", err
	}
	previous, err := LiveCertificates(ctx, server, tx, core.NewObject("tenantId", tenantID, "hostId", hostID))
	if err != nil {
		return nil, "", err
	}
	clockSkew := jsNumber(options.Get("clockSkewMs"))
	validBefore := now + jsNumber(options.Get("hostCertificateMs"))
	signingKey, err := OpenAuthority(server, authority)
	if err != nil {
		return nil, "", err
	}
	signed, err := SignSshCertificate(signingKey, sshRaw(
		"key", key,
		"serial", serial,
		"kind", float64(SshCertHost),
		"keyId", "host:"+name,
		"principals", principals,
		"validAfter", math.Floor((now-clockSkew)/1000),
		"validBefore", math.Floor(validBefore/1000),
	), name)
	if err != nil {
		return nil, "", err
	}
	line := jsString(signed.Get("line"))
	publicKey, err := SshKeyLine(sshBytes(key.Get("blob")), "")
	if err != nil {
		return nil, "", err
	}
	authorityID := jsString(authority.Get("id"))
	serialText := strconv.FormatUint(serial, 10)
	record, err := tx.Insert(ctx, "sshCertificates", core.NewObject(
		"id", ID(),
		"tenantId", tenantID,
		"uniqueKey", authorityID+":"+serialText,
		"kind", "host",
		"serial", serialText,
		"keyId", "host:"+name,
		"authorityId", authorityID,
		"hostId", hostID,
		"principals", stringsOf(principals),
		"extensions", []any{},
		"keyType", key.Get("type"),
		"publicKeyFingerprint", key.Get("fingerprint"),
		"publicKey", publicKey,
		"validAfter", now-clockSkew,
		"validBefore", validBefore,
		"issuedAt", now,
		"certificate", line,
		"expiresAt", validBefore+jsNumber(options.Get("recordRetentionMs")),
	))
	if err != nil {
		return nil, "", err
	}
	// One live certificate per host: earlier ones (another key, other names, another authority) end here.
	if _, err := api.revokeAll(ctx, tx, tenantID, previous, "superseded", "ssh-host:"+hostID); err != nil {
		return nil, "", err
	}
	return record, line, nil
}

// hostSetup is what an enrolled host installs; `syncHost` returns it again whenever the host checks in. renewal ""
// is none.
func (api *SshAPI) hostSetup(ctx context.Context, tx core.IamStore, tenant *core.Object, host *core.Object, line string, expiresAt float64, renewed bool, renewal string) (*core.Object, error) {
	server := api.server
	bundle, err := TrustBundle(ctx, server, tx, tenant, "member")
	if err != nil {
		return nil, err
	}
	krl, err := RevocationList(ctx, server, tx, tenant, "user")
	if err != nil {
		return nil, err
	}
	principals, err := PrincipalFiles(host)
	if err != nil {
		return nil, err
	}
	keyType := "ssh-ed25519"
	if hostKey := host.Get("hostKey"); !nullish(hostKey) {
		keyType = strings.Split(jsString(hostKey), " ")[0]
	}
	keyFile, ok := sshHostKeyFile[keyType]
	if !ok {
		keyFile = "ssh_host_ed25519_key"
	}
	certificatePath := "/etc/ssh/" + keyFile + "-cert.pub"
	sshdConfig := strings.Join([]string{
		"# Managed by better-iam: host " + jsString(host.Get("name")) + " of tenant " + jsString(tenant.Get("id")),
		"# The first value sshd reads wins, so this drop-in sorts first (check with sshd -T).",
		"TrustedUserCAKeys /etc/ssh/better-iam/user-ca.pub",
		"AuthorizedPrincipalsFile " + sshPrincipalsDirectory + "/%u",
		"RevokedKeys /etc/ssh/better-iam/revoked.krl",
		"HostCertificate " + certificatePath,
		"",
	}, "\n")
	setup := core.NewObject(
		"host", sshPublicHost(host),
		"certificate", line,
		"certificateExpiresAt", expiresAt,
		"certificateRenewed", renewed,
	)
	if renewal != "" {
		setup.Set("renewalToken", renewal)
	}
	files := []any{
		core.NewObject("path", certificatePath, "content", line+"\n", "mode", "0644"),
		core.NewObject("path", "/etc/ssh/better-iam/user-ca.pub", "content", bundle.Get("trustedUserCaKeys"), "mode", "0644"),
	}
	principals.Entries(func(login string, content any) bool {
		files = append(files, core.NewObject("path", sshPrincipalsDirectory+"/"+login, "content", content, "mode", "0644"))
		return true
	})
	files = append(files,
		core.NewObject("path", "/etc/ssh/better-iam/revoked.krl", "content", krl.Get("krl"), "mode", "0644", "encoding", "base64"),
		core.NewObject("path", "/etc/ssh/sshd_config.d/00-better-iam.conf", "content", sshdConfig, "mode", "0644"),
	)
	setup.Set("trustedUserCaKeys", bundle.Get("trustedUserCaKeys"))
	setup.Set("principals", principals)
	setup.Set("revocationList", krl.Get("krl"))
	setup.Set("revocationVersion", krl.Get("version"))
	setup.Set("files", files)
	setup.Set("managedDirectories", []any{sshPrincipalsDirectory})
	setup.Set("sshdConfig", sshdConfig)
	return setup, nil
}

func (api *SshAPI) hostAudit(ctx context.Context, tx core.IamStore, host *core.Object, action string, metadata *core.Object) error {
	return api.server.Events.RecordAudit(ctx, tx, core.NewObject(
		"id", ID(),
		"tenantId", host.Get("tenantId"),
		"actorId", "ssh-host:"+jsString(host.Get("id")),
		"action", action,
		"resourceId", "ssh/hosts/"+jsString(host.Get("name")),
		"outcome", "allow",
		"timestamp", float64(api.server.Now()),
		"metadata", metadata,
	))
}

// revokeAll revokes the certificates in records and bumps the revocation version once.
func (api *SshAPI) revokeAll(ctx context.Context, tx core.IamStore, tenantID string, records []*core.Object, reason string, actorID string) (int, error) {
	count := 0
	for _, record := range records {
		if !isUndefined(record.Get("revokedAt")) {
			continue
		}
		if _, err := MarkRevoked(ctx, api.server, tx, record, reason, actorID); err != nil {
			return 0, err
		}
		count++
	}
	if count > 0 {
		if err := BumpRevocationVersion(ctx, api.server, tx, tenantID); err != nil {
			return 0, err
		}
	}
	return count, nil
}

// sshCrossTenantRoot is a root override from outside the tenant (the platform's administrators acting in an
// organization).
func sshCrossTenantRoot(prepared *PreparedDecision, principal *Principal, tenantID string) bool {
	return IsRootOverride(prepared) && principal.Identity.Get("tenantId") != tenantID
}

// classifiedHosts gives, with security clearances, the classification labels of the hosts' `ssh-host` and
// `ssh-login` resources.
func (api *SshAPI) classifiedHosts(ctx context.Context, tx core.IamStore, tenantID string, hosts []*core.Object) (func(ResolvedResource) ResolvedResource, error) {
	resources := []ResolvedResource{}
	for _, host := range hosts {
		resource, err := HostResource(host)
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
		for _, login := range sshStrings(host.Get("logins")) {
			resource, err := LoginResource(host, login)
			if err != nil {
				return nil, err
			}
			resources = append(resources, resource)
		}
	}
	return ModuleResourceLabels(ctx, api.server, tx, tenantID, resources)
}

// sshAccessOf is the hosts and logins a principal may open, and what forwarding each host allows. logins nil: any;
// labeled gives the hosts' resources their classification labels (classifiedHosts).
func sshAccessOf(prepared *PreparedDecision, hosts []*core.Object, logins *orderedSet, labeled func(ResolvedResource) ResolvedResource) ([]sshAccess, error) {
	result := []sshAccess{}
	for _, host := range sshByName(hosts) {
		allowed := []string{}
		for _, login := range sshStrings(host.Get("logins")) {
			if logins != nil && !logins.Has(login) {
				continue
			}
			resource, err := LoginResource(host, login)
			if err != nil {
				return nil, err
			}
			decision, err := DecideOn(prepared, labeled(resource), SshLoginAction)
			if err != nil {
				return nil, err
			}
			if decision.Allowed {
				allowed = append(allowed, login)
			}
		}
		if len(allowed) == 0 {
			continue
		}
		forwarding := map[string]bool{}
		for _, action := range sshForwardingActionNames {
			resource, err := HostResource(host)
			if err != nil {
				return nil, err
			}
			decision, err := DecideOn(prepared, labeled(resource), action)
			if err != nil {
				return nil, err
			}
			forwarding[action] = decision.Allowed
		}
		result = append(result, sshAccess{host: host, logins: allowed, forwarding: forwarding})
	}
	return result, nil
}

// activate switches the signing key: the current active authority becomes `previous`.
func (api *SshAPI) activate(ctx context.Context, tx core.IamStore, pending *core.Object) (*core.Object, error) {
	now := float64(api.server.Now())
	current, err := TenantAuthorities(ctx, tx, jsString(pending.Get("tenantId")), jsString(pending.Get("kind")))
	if err != nil {
		return nil, err
	}
	for _, item := range current {
		if item.Get("status") == "active" {
			if _, err := tx.Put(ctx, "sshAuthorities", item.Spread(core.NewObject("status", "previous", "rotatedAt", now))); err != nil {
				return nil, err
			}
		}
	}
	return tx.Put(ctx, "sshAuthorities", pending.Spread(core.NewObject("status", "active", "activatedAt", now)))
}

// ActivateAuthority is POST {basePath}/ssh/activateAuthority. Makes a pending authority the signing key. The key it
// replaces stays trusted as previous, so certificates it issued keep working until they expire. Requires
// iam:ssh:manage.
func (api *SshAPI) ActivateAuthority(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshActivateAuthorityInput]) (Out[apitypes.SshActivateAuthorityOutput], error) {
	server := api.server
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshActivateAuthorityOutput]{}, err
	}
	authorityID, err := Text(input.Get("authorityId"), "authorityId")
	if err != nil {
		return Out[apitypes.SshActivateAuthorityOutput]{}, err
	}
	found, err := server.Scoped(ctx, server.Store, "sshAuthorities", authorityID, tenantID)
	if err != nil {
		return Out[apitypes.SshActivateAuthorityOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, sshManage, "ssh/authorities/"+jsString(found.Get("kind")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		if _, err := AssertSsh(server); err != nil {
			return nil, err
		}
		authority, err := server.Scoped(ctx, call.Tx, "sshAuthorities", found.Get("id"), tenantID)
		if err != nil {
			return nil, err
		}
		if authority.Get("status") != "pending" {
			return nil, core.NewIamError("INVALID_TRANSITION", "Only a pending authority can be activated", 409)
		}
		activated, err := api.activate(ctx, call.Tx, authority)
		if err != nil {
			return nil, err
		}
		return sshPublicAuthority(activated), nil
	}, false)
	if err != nil {
		return Out[apitypes.SshActivateAuthorityOutput]{}, err
	}
	return Out[apitypes.SshActivateAuthorityOutput]{Value: result}, nil
}

// ClientTrust is POST {basePath}/ssh/clientTrust. What a member's SSH client needs: knownhosts lines trusting the
// host authority for the organization's enrolled names (or its patterns), @revoked lines for host keys to refuse,
// and the host revocation list for `RevokedHostKeys`.
func (api *SshAPI) ClientTrust(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshClientTrustInput]) (Out[apitypes.SshClientTrustOutput], error) {
	server := api.server
	if _, err := AssertSsh(server); err != nil {
		return Out[apitypes.SshClientTrustOutput]{}, err
	}
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshClientTrustOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.SshClientTrustOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if principal.Session.Get("tenantId") != tenantID {
			return nil, core.NewIamError("ACCESS_DENIED", "Access denied", 403)
		}
		tenant, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		bundle, err := TrustBundle(ctx, server, tx, tenant, "member")
		if err != nil {
			return nil, err
		}
		hosts, err := RevocationList(ctx, server, tx, tenant, "host")
		if err != nil {
			return nil, err
		}
		return core.NewObject(
			"knownHosts", bundle.Get("knownHosts"),
			"revokedHostKeys", hosts.Get("krl"),
			"hostPatterns", bundle.Get("hostPatterns"),
		), nil
	})
	if err != nil {
		return Out[apitypes.SshClientTrustOutput]{}, err
	}
	return Out[apitypes.SshClientTrustOutput]{Value: result}, nil
}

// CreateHost is POST {basePath}/ssh/createHost. Registers a host and returns its one-time join token (shown once;
// valid for `joinTokenMs`). Its name and every address must be unused, within the caller's `iam:ssh:manage` scope,
// and names the organization can vouch for. Needs the authorities (`setup`). Requires iam:ssh:manage.
func (api *SshAPI) CreateHost(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshCreateHostInput]) (Out[apitypes.SshCreateHostOutput], error) {
	server := api.server
	name, err := SshHostName(input.Get("name"))
	if err != nil {
		return Out[apitypes.SshCreateHostOutput]{}, err
	}
	logins, err := sshHostLogins(input.Get("logins"))
	if err != nil {
		return Out[apitypes.SshCreateHostOutput]{}, err
	}
	addressList, err := sshHostAddresses(input.Get("addresses"))
	if err != nil {
		return Out[apitypes.SshCreateHostOutput]{}, err
	}
	addresses := sshWithout(addressList, name)
	labels, err := SshLabels(input.Get("labels"))
	if err != nil {
		return Out[apitypes.SshCreateHostOutput]{}, err
	}
	description := ""
	if value := input.Get("description"); !isUndefined(value) {
		if description, err = Text(value, "description", 512); err != nil {
			return Out[apitypes.SshCreateHostOutput]{}, err
		}
	}
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshCreateHostOutput]{}, err
	}
	resourceID := "ssh/hosts/" + name
	result, err := sshAudited(ctx, api, credential, tenantID, resourceID, func() (*core.Object, error) {
		return Operate(ctx, server.Operations, credential, tenantID, sshManage, resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, principal := call.Tx, call.Principal
			options, err := AssertSsh(server)
			if err != nil {
				return nil, err
			}
			realmID := jsString(call.Tenant.Get("id"))
			existing, err := HostByName(ctx, tx, realmID, name)
			if err != nil {
				return nil, err
			}
			if existing != nil {
				return nil, core.NewIamError("CONFLICT", "A host with this name already exists", 409)
			}
			// Creating the authorities is `setup`, a decision of its own.
			if _, err := ActiveAuthority(ctx, tx, realmID, "host"); err != nil {
				return nil, err
			}
			if err := api.assertNamesAllowed(ctx, tx, principal, realmID, append([]string{name}, addresses...), ""); err != nil {
				return nil, err
			}
			hostID := ID()
			secret := sshJoinToken(hostID)
			now := float64(server.Now())
			record := core.NewObject(
				"id", hostID,
				"tenantId", realmID,
				"uniqueKey", name,
				"name", name,
			)
			if description != "" {
				record.Set("description", description)
			}
			record.Set("addresses", stringsOf(addresses))
			record.Set("logins", stringsOf(logins))
			record.Set("labels", labels)
			record.Set("status", "pending")
			record.Set("joinTokenHash", Hash(secret))
			record.Set("joinTokenExpiresAt", now+jsNumber(options.Get("joinTokenMs")))
			record.Set("createdAt", now)
			record.Set("createdBy", principal.Identity.Get("id"))
			record.Set("updatedAt", now)
			host, err := tx.Insert(ctx, "sshHosts", record)
			if err != nil {
				return nil, err
			}
			return core.NewObject(
				"host", sshPublicHost(host),
				"joinToken", secret,
				"joinTokenExpiresAt", host.Get("joinTokenExpiresAt"),
			), nil
		}, false)
	})
	if err != nil {
		return Out[apitypes.SshCreateHostOutput]{}, err
	}
	return Out[apitypes.SshCreateHostOutput]{Value: result}, nil
}

// DeleteHost is POST {basePath}/ssh/deleteHost. Deletes a host; its certificate is revoked and its key published as
// revoked. Certificates naming it open nothing afterwards. Requires iam:ssh:manage.
func (api *SshAPI) DeleteHost(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshDeleteHostInput]) (Out[apitypes.SshDeleteHostOutput], error) {
	server := api.server
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshDeleteHostOutput]{}, err
	}
	name, err := api.hostRecordName(ctx, tenantID, input.Get("hostId"))
	if err != nil {
		return Out[apitypes.SshDeleteHostOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, sshManage, "ssh/hosts/"+name, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		if _, err := AssertSsh(server); err != nil {
			return nil, err
		}
		host, err := api.scopedHost(ctx, tx, tenantID, input.Get("hostId"))
		if err != nil {
			return nil, err
		}
		live, err := LiveCertificates(ctx, server, tx, core.NewObject("tenantId", tenantID, "hostId", host.Get("id")))
		if err != nil {
			return nil, err
		}
		if _, err := api.revokeAll(ctx, tx, tenantID, live, "host-deleted", jsString(call.Principal.Identity.Get("id"))); err != nil {
			return nil, err
		}
		if err := tx.Delete(ctx, "sshHosts", jsString(host.Get("id"))); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	}, false)
	if err != nil {
		return Out[apitypes.SshDeleteHostOutput]{}, err
	}
	return Out[apitypes.SshDeleteHostOutput]{Value: result}, nil
}

// DisableHost is POST {basePath}/ssh/disableHost. Takes a host out of service: its certificate is revoked, its key is
// published as revoked to clients, it can no longer sync, and no user certificate names it. Requires iam:ssh:manage.
func (api *SshAPI) DisableHost(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshDisableHostInput]) (Out[apitypes.SshDisableHostOutput], error) {
	server := api.server
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshDisableHostOutput]{}, err
	}
	name, err := api.hostRecordName(ctx, tenantID, input.Get("hostId"))
	if err != nil {
		return Out[apitypes.SshDisableHostOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, sshManage, "ssh/hosts/"+name, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		if _, err := AssertSsh(server); err != nil {
			return nil, err
		}
		host, err := api.scopedHost(ctx, tx, tenantID, input.Get("hostId"))
		if err != nil {
			return nil, err
		}
		if host.Get("status") == "disabled" {
			return sshPublicHost(host), nil
		}
		live, err := LiveCertificates(ctx, server, tx, core.NewObject("tenantId", tenantID, "hostId", host.Get("id")))
		if err != nil {
			return nil, err
		}
		if _, err := api.revokeAll(ctx, tx, tenantID, live, "host-disabled", jsString(call.Principal.Identity.Get("id"))); err != nil {
			return nil, err
		}
		rest := host.Spread()
		for _, key := range []string{"joinTokenHash", "joinTokenExpiresAt", "renewalTokenHash", "previousRenewalTokenHash"} {
			rest.Delete(key)
		}
		saved, err := tx.Put(ctx, "sshHosts", rest.Spread(core.NewObject("status", "disabled", "updatedAt", float64(server.Now()))))
		if err != nil {
			return nil, err
		}
		if err := BumpRevocationVersion(ctx, server, tx, tenantID); err != nil {
			return nil, err
		}
		return sshPublicHost(saved), nil
	}, false)
	if err != nil {
		return Out[apitypes.SshDisableHostOutput]{}, err
	}
	return Out[apitypes.SshDisableHostOutput]{Value: result}, nil
}

// sshHostOutcome is what a host call's transaction settles on: a refusal to record (with the host it names and extra
// metadata), or the setup to return.
type sshHostOutcome struct {
	refusal  *core.IamError
	host     *core.Object
	metadata *core.Object
	value    *core.Object
}

// EnrollHost is POST {basePath}/ssh/enrollHost (public: no request credential). Enrolls a host with its one-time join
// token and its public host key (not a security key): returns the host certificate, the trust and principals files
// sshd needs, the revocation list, and the renewal token for `syncHost`. Refusals of a real host's token are audited.
func (api *SshAPI) EnrollHost(ctx context.Context, input In[apitypes.SshEnrollHostInput]) (Out[apitypes.SshEnrollHostOutput], error) {
	server := api.server
	options, err := AssertSsh(server)
	if err != nil {
		return Out[apitypes.SshEnrollHostOutput]{}, err
	}
	joinToken := input.Get("joinToken")
	hostID, err := sshTokenHost(joinToken, "biam_sshj")
	if err != nil {
		return Out[apitypes.SshEnrollHostOutput]{}, err
	}
	known, err := server.Store.Get(ctx, "sshHosts", hostID)
	if err != nil {
		return Out[apitypes.SshEnrollHostOutput]{}, err
	}
	if known != nil {
		limit := int64(10)
		if err := server.Auth.LimitAttempt(ctx, jsString(known.Get("tenantId")), "ssh:enroll:"+hostID, auth.LimitAttemptOptions{Limit: &limit}); err != nil {
			return Out[apitypes.SshEnrollHostOutput]{}, err
		}
	}
	key, err := ParseSshPublicKey(input.Get("publicKey"), nil)
	if err != nil {
		return Out[apitypes.SshEnrollHostOutput]{}, err
	}
	presented := jsString(joinToken)
	outcome, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (sshHostOutcome, error) {
		host, err := tx.Get(ctx, "sshHosts", hostID)
		if err != nil {
			return sshHostOutcome{}, err
		}
		if host == nil ||
			host.Get("status") == "disabled" ||
			!truthy(host.Get("joinTokenHash")) ||
			!SameHash(host.Get("joinTokenHash"), Hash(presented)) ||
			jsNumber(coalesce(host.Get("joinTokenExpiresAt"), 0.0)) <= float64(server.Now()) {
			return sshHostOutcome{refusal: sshInvalidToken(), host: host}, nil
		}
		tenantID := jsString(host.Get("tenantId"))
		tenant, err := api.activeTenant(ctx, tx, tenantID)
		if err != nil {
			return sshHostOutcome{}, err
		}
		if err := AssertHostKeyFree(ctx, tx, tenantID, jsString(host.Get("id")), key); err != nil {
			return sshHostOutcome{}, err
		}
		record, line, err := api.certifyHost(ctx, tx, host, key, options)
		if err != nil {
			return sshHostOutcome{}, err
		}
		renewal := sshRenewalToken(jsString(host.Get("id")))
		now := float64(server.Now())
		rest := host.Spread()
		for _, field := range []string{"joinTokenHash", "joinTokenExpiresAt", "previousRenewalTokenHash"} {
			rest.Delete(field)
		}
		hostKey, err := SshKeyLine(sshBytes(key.Get("blob")), "")
		if err != nil {
			return sshHostOutcome{}, err
		}
		saved, err := tx.Put(ctx, "sshHosts", rest.Spread(core.NewObject(
			"status", "enrolled",
			"hostKey", hostKey,
			"hostKeyFingerprint", key.Get("fingerprint"),
			"certificateId", record.Get("id"),
			"certificateExpiresAt", record.Get("validBefore"),
			"renewalTokenHash", Hash(renewal),
			"enrolledAt", now,
			"renewedAt", now,
			"lastSeenAt", now,
			"updatedAt", now,
		)))
		if err != nil {
			return sshHostOutcome{}, err
		}
		if err := api.hostAudit(ctx, tx, saved, "ssh:host:enroll", core.NewObject(
			"serial", record.Get("serial"),
			"fingerprint", key.Get("fingerprint"),
			"keyType", key.Get("type"),
		)); err != nil {
			return sshHostOutcome{}, err
		}
		setup, err := api.hostSetup(ctx, tx, tenant, saved, line, jsNumber(record.Get("validBefore")), true, renewal)
		if err != nil {
			return sshHostOutcome{}, err
		}
		return sshHostOutcome{value: setup}, nil
	})
	if err != nil {
		return Out[apitypes.SshEnrollHostOutput]{}, err
	}
	if outcome.refusal != nil {
		return Out[apitypes.SshEnrollHostOutput]{}, api.refuseHost(ctx, outcome.host, "ssh:host:enroll", outcome.refusal, nil)
	}
	return Out[apitypes.SshEnrollHostOutput]{Value: outcome.value}, nil
}

// GetCertificate is POST {basePath}/ssh/getCertificate. One certificate record: kind, serial, key ID, principals,
// hosts and logins, extensions, key fingerprint, validity, and revocation details. Requires iam:ssh:read.
func (api *SshAPI) GetCertificate(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshGetCertificateInput]) (Out[apitypes.SshGetCertificateOutput], error) {
	server := api.server
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshGetCertificateOutput]{}, err
	}
	certificateID, err := Text(input.Get("certificateId"), "certificateId")
	if err != nil {
		return Out[apitypes.SshGetCertificateOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, sshRead, "ssh/certificates/"+certificateID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		record, err := server.Scoped(ctx, call.Tx, "sshCertificates", input.Get("certificateId"), jsString(call.Tenant.Get("id")))
		if err != nil {
			return nil, err
		}
		return sshCertificateView(record, float64(server.Now())), nil
	}, false)
	if err != nil {
		return Out[apitypes.SshGetCertificateOutput]{}, err
	}
	return Out[apitypes.SshGetCertificateOutput]{Value: result}, nil
}

// GetHost is POST {basePath}/ssh/getHost. One host: status, addresses, logins, labels, host key fingerprint,
// certificate expiry and when it last synced. Token hashes never appear. Requires iam:ssh:read.
func (api *SshAPI) GetHost(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshGetHostInput]) (Out[apitypes.SshGetHostOutput], error) {
	server := api.server
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshGetHostOutput]{}, err
	}
	name, err := api.hostRecordName(ctx, tenantID, input.Get("hostId"))
	if err != nil {
		return Out[apitypes.SshGetHostOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, sshRead, "ssh/hosts/"+name, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		host, err := api.scopedHost(ctx, call.Tx, tenantID, input.Get("hostId"))
		if err != nil {
			return nil, err
		}
		return sshPublicHost(host), nil
	}, false)
	if err != nil {
		return Out[apitypes.SshGetHostOutput]{}, err
	}
	return Out[apitypes.SshGetHostOutput]{Value: result}, nil
}

// GetSettings is POST {basePath}/ssh/getSettings. The tenant's settings (MFA, security keys, source-address binding,
// default and maximum lifetimes, host patterns), the revocation list version, and the deployment's ceiling for
// maxCertificateMs. Requires iam:ssh:read.
func (api *SshAPI) GetSettings(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshGetSettingsInput]) (Out[apitypes.SshGetSettingsOutput], error) {
	server := api.server
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshGetSettingsOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, sshRead, "ssh/settings", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		settings, err := LoadSshSettings(ctx, server, call.Tx, jsString(call.Tenant.Get("id")))
		if err != nil {
			return nil, err
		}
		options, err := AssertSsh(server)
		if err != nil {
			return nil, err
		}
		return sshSettingsView(settings, options), nil
	}, false)
	if err != nil {
		return Out[apitypes.SshGetSettingsOutput]{}, err
	}
	return Out[apitypes.SshGetSettingsOutput]{Value: result}, nil
}

// sshIssueOutcome is what the issuing transaction settles on: a refusal (committed with its audit record) or the
// certificate.
type sshIssueOutcome struct {
	refusal *core.IamError
	value   *core.Object
	usage   bool
}

// IssueCertificate is POST {basePath}/ssh/issueCertificate. Issues a user certificate for the caller's public key,
// naming every requested host and login that policies allow (`ssh:login` on `ssh-login/{host}/{login}`), with
// forwarding extensions only where every named host allows them. The lifetime never outlives the caller's session or
// account, nor a time-limited grant that allows `ssh:login`; certificates for agents acting for people last ten
// minutes. Rate limited per identity (`ssh.issuanceLimit`). Audited as `ssh:certificate:issue`; a refusal is audited
// as a denied `ssh:login`.
func (api *SshAPI) IssueCertificate(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshIssueCertificateInput]) (Out[apitypes.SshIssueCertificateOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.SshIssueCertificateOutput], error) {
		return Out[apitypes.SshIssueCertificateOutput]{}, err
	}
	options, err := AssertSsh(server)
	if err != nil {
		return fail(err)
	}
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return fail(err)
	}
	key, err := ParseSshPublicKey(input.Get("publicKey"), nil)
	if err != nil {
		return fail(err)
	}
	var requestedHosts []string
	hostsRequested := !isUndefined(input.Get("hosts"))
	if hostsRequested {
		if requestedHosts, err = sshListOf(input.Get("hosts"), "hosts", 256, SshHostName); err != nil {
			return fail(err)
		}
	}
	var requestedLogins *orderedSet
	if value := input.Get("logins"); !isUndefined(value) {
		logins, err := sshListOf(value, "logins", 64, SshLogin)
		if err != nil {
			return fail(err)
		}
		requestedLogins = newOrderedSet(logins...)
	}
	maxUser := jsNumber(options.Get("maxUserCertificateMs"))
	var ttl *float64
	if value := input.Get("ttlMs"); !isUndefined(value) {
		number, err := Integer(value, "ttlMs", 60_000, maxUser)
		if err != nil {
			return fail(err)
		}
		ttl = &number
	}
	reason := ""
	if value := input.Get("reason"); !isUndefined(value) {
		if reason, err = Text(value, "reason", 512); err != nil {
			return fail(err)
		}
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return fail(err)
	}
	limit := int64(jsNumber(options.Get("issuanceLimit")))
	if err := server.Auth.LimitAttempt(ctx, tenantID, "ssh:issue:"+jsString(authenticated.Identity.Get("id")), auth.LimitAttemptOptions{Limit: &limit}); err != nil {
		return fail(err)
	}
	outcome, err := Span(server.Observe, "operation", "ssh:certificate:issue", tenantID, func() (sshIssueOutcome, error) {
		return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (sshIssueOutcome, error) {
			principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
			if err != nil {
				return sshIssueOutcome{}, err
			}
			tenant, err := server.Tenant(ctx, tx, tenantID)
			if err != nil {
				return sshIssueOutcome{}, err
			}
			target := "ssh-login/*"
			if len(requestedHosts) > 0 {
				target = jsSlice("ssh-login/"+strings.Join(requestedHosts, ","), 256)
			}
			refuse := func(code, message string, status int) (sshIssueOutcome, error) {
				if err := server.Events.Audit(ctx, tx, principal, SshLoginAction, tenantID, target, "deny", false, core.NewObject(
					"reason", code,
					"fingerprint", key.Get("fingerprint"),
				)); err != nil {
					return sshIssueOutcome{}, err
				}
				return sshIssueOutcome{refusal: core.NewIamError(code, message, status)}, nil
			}
			identity, session := principal.Identity, principal.Session
			if truthy(session.Get("impersonatorId")) {
				return refuse("IMPERSONATION_RESTRICTED", "SSH certificates cannot be issued while viewing as someone", 403)
			}
			// Decided first, so a principal of another tenant learns nothing about this one's hosts or settings.
			prepared, err := server.Decisions.PrepareDecision(ctx, tx, principal, tenant, SshLoginAction)
			if err != nil {
				return sshIssueOutcome{}, err
			}
			if prepared.Fixed != nil && !prepared.Fixed.Allowed {
				return refuse("ACCESS_DENIED", "Access denied", 403)
			}
			// The platform's root override never opens an organization's servers: a root administrator needs a role
			// in that organization like anyone else (only the root tenant's own hosts are theirs).
			if sshCrossTenantRoot(prepared, principal, tenantID) {
				return refuse("ROOT_SSH_RESTRICTED", "Platform administrators need a role in this organization to open its hosts", 403)
			}
			settings, err := LoadSshSettings(ctx, server, tx, tenantID)
			if err != nil {
				return sshIssueOutcome{}, err
			}
			if truthy(settings.Get("requireMfa")) && identity.Get("kind") == "user" && !truthy(session.Get("mfa")) {
				return refuse("MFA_REQUIRED", "Sign in with multi-factor authentication to get an SSH certificate", 403)
			}
			securityKey := truthy(key.Get("securityKey"))
			if truthy(settings.Get("requireSecurityKey")) && !securityKey {
				return refuse("SECURITY_KEY_REQUIRED", "This organization certifies only hardware security keys (ed25519-sk or ecdsa-sk)", 403)
			}
			authority, err := ActiveAuthority(ctx, tx, tenantID, "user")
			if err != nil {
				return sshIssueOutcome{}, err
			}
			authorities, err := TenantAuthorities(ctx, tx, tenantID, "")
			if err != nil {
				return sshIssueOutcome{}, err
			}
			for _, item := range authorities {
				if item.Get("fingerprint") == key.Get("fingerprint") {
					return sshIssueOutcome{refusal: invalidInput("An authority key cannot be certified")}, nil
				}
			}
			var hosts []*core.Object
			if hostsRequested {
				hosts = []*core.Object{}
				for _, name := range requestedHosts {
					host, err := HostByName(ctx, tx, tenantID, name)
					if err != nil {
						return sshIssueOutcome{}, err
					}
					if host == nil || host.Get("status") != "enrolled" {
						return sshIssueOutcome{refusal: core.NewIamError("NOT_FOUND", "No enrolled host is named "+name, 404)}, nil
					}
					hosts = append(hosts, host)
				}
			} else if hosts, err = tx.Find(ctx, "sshHosts", core.NewObject("tenantId", tenantID, "status", "enrolled"), nil); err != nil {
				return sshIssueOutcome{}, err
			}
			labeled, err := api.classifiedHosts(ctx, tx, tenantID, hosts)
			if err != nil {
				return sshIssueOutcome{}, err
			}
			access, err := sshAccessOf(prepared, hosts, requestedLogins, labeled)
			if err != nil {
				return sshIssueOutcome{}, err
			}
			if len(access) == 0 {
				return refuse("ACCESS_DENIED", "Access denied", 403)
			}
			maxHosts := jsNumber(options.Get("maxHostsPerCertificate"))
			if float64(len(access)) > maxHosts {
				return sshIssueOutcome{refusal: core.NewIamError("TOO_MANY_HOSTS",
					"The certificate would name "+strconv.Itoa(len(access))+" hosts; name at most "+jsString(maxHosts)+" with hosts", 400)}, nil
			}
			principals := []string{}
			for _, entry := range access {
				for _, login := range entry.logins {
					principalName, err := SshLoginPrincipal(login, jsString(entry.host.Get("name")))
					if err != nil {
						return sshIssueOutcome{}, err
					}
					principals = append(principals, principalName)
				}
			}
			if len(principals) > 256 {
				return sshIssueOutcome{refusal: core.NewIamError("TOO_MANY_HOSTS", "Name fewer hosts or logins (at most 256 principals)", 400)}, nil
			}
			extensions := []string{"permit-pty", "permit-user-rc"}
			for _, action := range sshForwardingActionNames {
				every := true
				for _, entry := range access {
					if !entry.forwarding[action] {
						every = false
						break
					}
				}
				if every {
					extensions = append(extensions, jsString(SshForwardingActions.Get(action)))
				}
			}
			now := float64(server.Now())
			lifetime := jsNumber(settings.Get("defaultCertificateMs"))
			if ttl != nil {
				lifetime = *ttl
			}
			validBefore := now + math.Min(lifetime, jsNumber(settings.Get("maxCertificateMs")))
			validBefore = math.Min(validBefore, jsNumber(session.Get("expiresAt")))
			if expiresAt, ok := identity.Get("expiresAt").(float64); ok {
				validBefore = math.Min(validBefore, expiresAt)
			}
			if session.Get("kind") == "delegated" {
				validBefore = math.Min(validBefore, now+DelegatedCertificateMs)
			}
			if !IsRootOverride(prepared) {
				if validBefore, err = SshGrantDeadline(ctx, server, tx, principal, tenantID, validBefore); err != nil {
					return sshIssueOutcome{}, err
				}
			}
			if validBefore < now+60_000 {
				return sshIssueOutcome{refusal: core.NewIamError("SESSION_EXPIRING",
					"This session or the access that allows it ends within a minute; renew it first", 401)}, nil
			}
			criticalOptions := core.NewObject()
			sourceAddress := ""
			if truthy(settings.Get("bindSourceAddress")) {
				ip := ""
				if client := server.Auth.CurrentClient(ctx); client != nil {
					ip = client.IP
				}
				family := 0
				if ip != "" {
					family = nodeIsIP(ip)
				}
				if family == 0 {
					return sshIssueOutcome{refusal: core.NewIamError("SOURCE_ADDRESS_UNKNOWN",
						"This organization binds certificates to your address, which could not be determined", 400)}, nil
				}
				bits := "32"
				if family == 6 {
					bits = "128"
				}
				sourceAddress = ip + "/" + bits
				criticalOptions.Set("source-address", sourceAddress)
			}
			if securityKey && truthy(settings.Get("requireUserVerification")) {
				criticalOptions.Set("verify-required", "")
			}
			serialValue, err := SshSerial()
			if err != nil {
				return sshIssueOutcome{}, err
			}
			serial := serialValue.(uint64)
			keyID, err := CertificateKeyID(principal)
			if err != nil {
				return sshIssueOutcome{}, err
			}
			signingKey, err := OpenAuthority(server, authority)
			if err != nil {
				return sshIssueOutcome{}, err
			}
			comment := ""
			if text, ok := key.Get("comment").(string); ok {
				comment = sshPrintable(text)
			}
			clockSkew := jsNumber(options.Get("clockSkewMs"))
			signed, err := SignSshCertificate(signingKey, sshRaw(
				"key", key,
				"serial", serial,
				"kind", float64(SshCertUser),
				"keyId", keyID,
				"principals", principals,
				"validAfter", math.Floor((now-clockSkew)/1000),
				"validBefore", math.Floor(validBefore/1000),
				"criticalOptions", criticalOptions,
				"extensions", extensions,
			), comment)
			if err != nil {
				return sshIssueOutcome{}, err
			}
			rootOverride := IsRootOverride(prepared)
			// The device this request proved, which the sweep judges device conditions by (devices.ts).
			device, err := PresentedDevice(ctx, tx, principal, int64(now))
			if err != nil {
				return sshIssueOutcome{}, err
			}
			authorityID := jsString(authority.Get("id"))
			serialText := strconv.FormatUint(serial, 10)
			accessList := make([]any, len(access))
			hostNames := make([]any, len(access))
			hostViews := make([]any, len(access))
			for index, entry := range access {
				name := entry.host.Get("name")
				accessList[index] = core.NewObject("host", name, "logins", stringsOf(entry.logins))
				hostNames[index] = name
				hostViews[index] = core.NewObject("name", name, "addresses", entry.host.Get("addresses"), "logins", stringsOf(entry.logins))
			}
			sortedExtensions := append([]string(nil), extensions...)
			sort.SliceStable(sortedExtensions, func(i, j int) bool { return compareUTF16(sortedExtensions[i], sortedExtensions[j]) < 0 })
			record := core.NewObject(
				"id", ID(),
				"tenantId", tenantID,
				"uniqueKey", authorityID+":"+serialText,
				"kind", "user",
				"serial", serialText,
				"keyId", keyID,
				"authorityId", authorityID,
				"identityId", identity.Get("id"),
				"sessionId", session.Get("id"),
				"sessionKind", session.Get("kind"),
				"mfa", session.Get("mfa"),
			)
			if device != nil {
				record.Set("deviceKeyId", member(device.Get("key"), "id"))
			}
			record.Set("principals", stringsOf(principals))
			record.Set("access", accessList)
			record.Set("extensions", stringsOf(sortedExtensions))
			if sourceAddress != "" {
				record.Set("sourceAddress", sourceAddress)
			}
			record.Set("keyType", key.Get("type"))
			record.Set("publicKeyFingerprint", key.Get("fingerprint"))
			record.Set("validAfter", now-clockSkew)
			record.Set("validBefore", validBefore)
			record.Set("issuedAt", now)
			if reason != "" {
				record.Set("reason", reason)
			}
			record.Set("expiresAt", validBefore+jsNumber(options.Get("recordRetentionMs")))
			if record, err = tx.Insert(ctx, "sshCertificates", record); err != nil {
				return sshIssueOutcome{}, err
			}
			metadata := core.NewObject(
				"serial", record.Get("serial"),
				"keyId", keyID,
				"hosts", hostNames,
				"principals", float64(len(principals)),
				"validBefore", validBefore,
				"fingerprint", key.Get("fingerprint"),
				"keyType", key.Get("type"),
			)
			if reason != "" {
				metadata.Set("reason", reason)
			}
			if err := server.Events.Audit(ctx, tx, principal, "ssh:certificate:issue", tenantID, "ssh/certificates/"+jsString(record.Get("id")), "allow", rootOverride, metadata); err != nil {
				return sshIssueOutcome{}, err
			}
			bundle, err := TrustBundle(ctx, server, tx, tenant, "member")
			if err != nil {
				return sshIssueOutcome{}, err
			}
			hostList, err := RevocationList(ctx, server, tx, tenant, "host")
			if err != nil {
				return sshIssueOutcome{}, err
			}
			value := core.NewObject(
				"id", record.Get("id"),
				"certificate", signed.Get("line"),
				"serial", record.Get("serial"),
				"keyId", keyID,
				"principals", stringsOf(principals),
				"validAfter", record.Get("validAfter"),
				"validBefore", validBefore,
				"extensions", record.Get("extensions"),
			)
			if sourceAddress != "" {
				value.Set("sourceAddress", sourceAddress)
			}
			value.Set("hosts", hostViews)
			value.Set("knownHosts", bundle.Get("knownHosts"))
			value.Set("revokedHostKeys", hostList.Get("krl"))
			return sshIssueOutcome{usage: !rootOverride, value: value}, nil
		})
	}, nil, nil)
	if err != nil {
		return fail(err)
	}
	if outcome.refusal != nil {
		return fail(outcome.refusal)
	}
	// Using SSH access is using `ssh:login` (not a root override), for role mining and right-sizing.
	if outcome.usage {
		server.Usage.Record(tenantID, jsString(authenticated.Identity.Get("id")), SshLoginAction)
	}
	return Out[apitypes.SshIssueCertificateOutput]{Value: outcome.value}, nil
}

// ListAuthorities is POST {basePath}/ssh/listAuthorities. Every authority key of the tenant, retired ones included:
// kind (user or host), status (pending, active, previous, retired), public key and fingerprint. Private keys never
// appear. Requires iam:ssh:read.
func (api *SshAPI) ListAuthorities(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshListAuthoritiesInput]) (Out[apitypes.SshListAuthoritiesOutput], error) {
	server := api.server
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshListAuthoritiesOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, sshRead, "ssh/authorities", func(ctx context.Context, call MutationContext) ([]any, error) {
		if _, err := AssertSsh(server); err != nil {
			return nil, err
		}
		authorities, err := TenantAuthorities(ctx, call.Tx, jsString(call.Tenant.Get("id")), "")
		if err != nil {
			return nil, err
		}
		return sshPublicAuthorities(authorities), nil
	}, false)
	if err != nil {
		return Out[apitypes.SshListAuthoritiesOutput]{}, err
	}
	return Out[apitypes.SshListAuthoritiesOutput]{Value: result}, nil
}

// ListCertificates is POST {basePath}/ssh/listCertificates. Issued certificates, newest first, filtered by kind,
// identityId, hostId or status (active, revoked, expired), paged with limit (at most 500) and offset. Requires
// iam:ssh:read.
func (api *SshAPI) ListCertificates(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshListCertificatesInput]) (Out[apitypes.SshListCertificatesOutput], error) {
	server := api.server
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshListCertificatesOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, sshRead, "ssh/certificates", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		if _, err := AssertSsh(server); err != nil {
			return nil, err
		}
		limit, err := Integer(coalesce(input.Get("limit"), 100.0), "limit", 1, 500)
		if err != nil {
			return nil, err
		}
		offset, err := Integer(coalesce(input.Get("offset"), 0.0), "offset", 0, 1_000_000)
		if err != nil {
			return nil, err
		}
		filter := core.NewObject("tenantId", call.Tenant.Get("id"))
		if kind := input.Get("kind"); !isUndefined(kind) {
			filter.Set("kind", kind)
		}
		if value := input.Get("identityId"); !isUndefined(value) {
			identityID, err := Text(value, "identityId")
			if err != nil {
				return nil, err
			}
			filter.Set("identityId", identityID)
		}
		if value := input.Get("hostId"); !isUndefined(value) {
			hostID, err := Text(value, "hostId")
			if err != nil {
				return nil, err
			}
			filter.Set("hostId", hostID)
		}
		now := float64(server.Now())
		records, err := call.Tx.Find(ctx, "sshCertificates", filter, nil)
		if err != nil {
			return nil, err
		}
		status := input.Get("status")
		views := []*core.Object{}
		for _, record := range records {
			view := sshCertificateView(record, now)
			if isUndefined(status) || view.Get("status") == status {
				views = append(views, view)
			}
		}
		sshNewestFirst(views)
		start := int(math.Min(offset, float64(len(views))))
		end := int(math.Min(offset+limit, float64(len(views))))
		page := make([]any, 0, end-start)
		for _, view := range views[start:end] {
			page = append(page, view)
		}
		return core.NewObject("certificates", page, "total", float64(len(views))), nil
	}, false)
	if err != nil {
		return Out[apitypes.SshListCertificatesOutput]{}, err
	}
	return Out[apitypes.SshListCertificatesOutput]{Value: result}, nil
}

// ListHosts is POST {basePath}/ssh/listHosts. The tenant's hosts by name, filtered by status, exact labels, or a
// query over names, addresses and descriptions. Requires iam:ssh:read.
func (api *SshAPI) ListHosts(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshListHostsInput]) (Out[apitypes.SshListHostsOutput], error) {
	server := api.server
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshListHostsOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, sshRead, "ssh/hosts", func(ctx context.Context, call MutationContext) ([]any, error) {
		if _, err := AssertSsh(server); err != nil {
			return nil, err
		}
		labels := core.NewObject()
		if value := input.Get("labels"); !isUndefined(value) {
			if labels, err = SshLabels(value); err != nil {
				return nil, err
			}
		}
		query, hasQuery := "", false
		if value := input.Get("query"); !isUndefined(value) {
			text, err := Text(value, "query", 128)
			if err != nil {
				return nil, err
			}
			query, hasQuery = core.JSLower(text), true
		}
		filter := core.NewObject("tenantId", call.Tenant.Get("id"))
		if status := input.Get("status"); truthy(status) {
			filter.Set("status", status)
		}
		hosts, err := call.Tx.Find(ctx, "sshHosts", filter, nil)
		if err != nil {
			return nil, err
		}
		matched := []*core.Object{}
		for _, host := range hosts {
			every := true
			labels.Entries(func(key string, value any) bool {
				if member(host.Get("labels"), key) != value {
					every = false
					return false
				}
				return true
			})
			if !every {
				continue
			}
			if hasQuery && query != "" {
				found := strings.Contains(jsString(host.Get("name")), query)
				for _, address := range sshStrings(host.Get("addresses")) {
					found = found || strings.Contains(address, query)
				}
				description := ""
				if value := host.Get("description"); !nullish(value) {
					description = jsString(value)
				}
				found = found || strings.Contains(core.JSLower(description), query)
				if !found {
					continue
				}
			}
			matched = append(matched, host)
		}
		out := []any{}
		for _, host := range sshByName(matched) {
			out = append(out, sshPublicHost(host))
		}
		return out, nil
	}, false)
	if err != nil {
		return Out[apitypes.SshListHostsOutput]{}, err
	}
	return Out[apitypes.SshListHostsOutput]{Value: result}, nil
}

// MyAccess is POST {basePath}/ssh/myAccess. The enrolled hosts the caller may open, with the logins and forwarding
// policies allow, and the settings that affect a request (MFA, security keys, lifetimes). No permission needed.
func (api *SshAPI) MyAccess(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshMyAccessInput]) (Out[apitypes.SshMyAccessOutput], error) {
	server := api.server
	if _, err := AssertSsh(server); err != nil {
		return Out[apitypes.SshMyAccessOutput]{}, err
	}
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshMyAccessOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.SshMyAccessOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		tenant, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		prepared, err := server.Decisions.PrepareDecision(ctx, tx, principal, tenant, SshLoginAction)
		if err != nil {
			return nil, err
		}
		refused := (prepared.Fixed != nil && !prepared.Fixed.Allowed) || sshCrossTenantRoot(prepared, principal, tenantID)
		settings, err := LoadSshSettings(ctx, server, tx, tenantID)
		if err != nil {
			return nil, err
		}
		hosts := []*core.Object{}
		if !refused {
			if hosts, err = tx.Find(ctx, "sshHosts", core.NewObject("tenantId", tenantID, "status", "enrolled"), nil); err != nil {
				return nil, err
			}
		}
		labeled, err := api.classifiedHosts(ctx, tx, tenantID, hosts)
		if err != nil {
			return nil, err
		}
		access, err := sshAccessOf(prepared, hosts, nil, labeled)
		if err != nil {
			return nil, err
		}
		view := make([]any, len(access))
		for index, entry := range access {
			host := entry.host
			item := core.NewObject("name", host.Get("name"))
			if description := host.Get("description"); truthy(description) {
				item.Set("description", description)
			}
			item.Set("addresses", host.Get("addresses"))
			item.Set("labels", host.Get("labels"))
			item.Set("logins", stringsOf(entry.logins))
			item.Set("forwarding", core.NewObject(
				"port", entry.forwarding["ssh:port-forward"],
				"agent", entry.forwarding["ssh:agent-forward"],
				"x11", entry.forwarding["ssh:x11-forward"],
			))
			view[index] = item
		}
		return core.NewObject(
			"hosts", view,
			"requireMfa", settings.Get("requireMfa"),
			"requireSecurityKey", settings.Get("requireSecurityKey"),
			"defaultCertificateMs", settings.Get("defaultCertificateMs"),
			"maxCertificateMs", settings.Get("maxCertificateMs"),
		), nil
	})
	if err != nil {
		return Out[apitypes.SshMyAccessOutput]{}, err
	}
	return Out[apitypes.SshMyAccessOutput]{Value: result}, nil
}

// MyCertificates is POST {basePath}/ssh/myCertificates. The caller's own certificates in the tenant, newest first
// (the last 100), with their status.
func (api *SshAPI) MyCertificates(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshMyCertificatesInput]) (Out[apitypes.SshMyCertificatesOutput], error) {
	server := api.server
	if _, err := AssertSsh(server); err != nil {
		return Out[apitypes.SshMyCertificatesOutput]{}, err
	}
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshMyCertificatesOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.SshMyCertificatesOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]any, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		now := float64(server.Now())
		// An agent acting for the person sees only the certificates its own session obtained.
		delegated := principal.Session.Get("kind") == "delegated"
		records, err := tx.Find(ctx, "sshCertificates", core.NewObject("tenantId", tenantID, "identityId", principal.Identity.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		mine := []*core.Object{}
		for _, record := range records {
			if !delegated || record.Get("sessionId") == principal.Session.Get("id") {
				mine = append(mine, record)
			}
		}
		sshNewestFirst(mine)
		if len(mine) > 100 {
			mine = mine[:100]
		}
		out := make([]any, len(mine))
		for index, record := range mine {
			out[index] = sshCertificateView(record, now)
		}
		return out, nil
	})
	if err != nil {
		return Out[apitypes.SshMyCertificatesOutput]{}, err
	}
	return Out[apitypes.SshMyCertificatesOutput]{Value: result}, nil
}

// ResetJoinToken is POST {basePath}/ssh/resetJoinToken. Returns a fresh one-time join token, for a rebuilt server or
// to bring a disabled host back. The host's renewal token stops working; re-enrolling revokes its previous
// certificates as superseded. Requires iam:ssh:manage.
func (api *SshAPI) ResetJoinToken(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshResetJoinTokenInput]) (Out[apitypes.SshResetJoinTokenOutput], error) {
	server := api.server
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshResetJoinTokenOutput]{}, err
	}
	name, err := api.hostRecordName(ctx, tenantID, input.Get("hostId"))
	if err != nil {
		return Out[apitypes.SshResetJoinTokenOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, sshManage, "ssh/hosts/"+name, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		options, err := AssertSsh(server)
		if err != nil {
			return nil, err
		}
		host, err := api.scopedHost(ctx, call.Tx, tenantID, input.Get("hostId"))
		if err != nil {
			return nil, err
		}
		secret := sshJoinToken(jsString(host.Get("id")))
		rest := host.Spread()
		rest.Delete("renewalTokenHash")
		rest.Delete("previousRenewalTokenHash")
		status := host.Get("status")
		if status == "disabled" {
			status = "pending"
		}
		saved, err := call.Tx.Put(ctx, "sshHosts", rest.Spread(core.NewObject(
			"status", status,
			"joinTokenHash", Hash(secret),
			"joinTokenExpiresAt", float64(server.Now())+jsNumber(options.Get("joinTokenMs")),
			"updatedAt", float64(server.Now()),
		)))
		if err != nil {
			return nil, err
		}
		return core.NewObject(
			"host", sshPublicHost(saved),
			"joinToken", secret,
			"joinTokenExpiresAt", saved.Get("joinTokenExpiresAt"),
		), nil
	}, false)
	if err != nil {
		return Out[apitypes.SshResetJoinTokenOutput]{}, err
	}
	return Out[apitypes.SshResetJoinTokenOutput]{Value: result}, nil
}

// RetireAuthority is POST {basePath}/ssh/retireAuthority. Stops trusting a previous (or pending) authority. Refused
// while certificates it signed are still valid, unless `force` (they are revoked). Requires iam:ssh:manage.
func (api *SshAPI) RetireAuthority(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshRetireAuthorityInput]) (Out[apitypes.SshRetireAuthorityOutput], error) {
	server := api.server
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshRetireAuthorityOutput]{}, err
	}
	authorityID, err := Text(input.Get("authorityId"), "authorityId")
	if err != nil {
		return Out[apitypes.SshRetireAuthorityOutput]{}, err
	}
	found, err := server.Scoped(ctx, server.Store, "sshAuthorities", authorityID, tenantID)
	if err != nil {
		return Out[apitypes.SshRetireAuthorityOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, sshManage, "ssh/authorities/"+jsString(found.Get("kind")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		if _, err := AssertSsh(server); err != nil {
			return nil, err
		}
		authority, err := server.Scoped(ctx, tx, "sshAuthorities", found.Get("id"), tenantID)
		if err != nil {
			return nil, err
		}
		if status := authority.Get("status"); status != "previous" && status != "pending" {
			return nil, core.NewIamError("INVALID_TRANSITION", "Only a previous or pending authority can be retired", 409)
		}
		live, err := LiveCertificates(ctx, server, tx, core.NewObject("tenantId", tenantID, "authorityId", authority.Get("id")))
		if err != nil {
			return nil, err
		}
		if len(live) > 0 && input.Get("force") != true {
			return nil, core.NewIamError("RESOURCE_IN_USE", strconv.Itoa(len(live))+" certificates signed by this authority are still valid", 409)
		}
		if _, err := api.revokeAll(ctx, tx, tenantID, live, "authority-retired", jsString(call.Principal.Identity.Get("id"))); err != nil {
			return nil, err
		}
		retired, err := tx.Put(ctx, "sshAuthorities", authority.Spread(core.NewObject("status", "retired", "retiredAt", float64(server.Now()))))
		if err != nil {
			return nil, err
		}
		return sshPublicAuthority(retired), nil
	}, false)
	if err != nil {
		return Out[apitypes.SshRetireAuthorityOutput]{}, err
	}
	return Out[apitypes.SshRetireAuthorityOutput]{Value: result}, nil
}

// RevocationList is POST {basePath}/ssh/revocationList (public: no request credential). The tenant's key revocation
// list: `user` (default, for sshd `RevokedKeys`) or `host` (for ssh `RevokedHostKeys`), base64. Public, like a
// certificate revocation list: serials and public keys only. Served for suspended organizations too (every user
// certificate is then revoked).
func (api *SshAPI) RevocationList(ctx context.Context, input In[apitypes.SshRevocationListInput]) (Out[apitypes.SshRevocationListOutput], error) {
	server := api.server
	if _, err := AssertSsh(server); err != nil {
		return Out[apitypes.SshRevocationListOutput]{}, err
	}
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshRevocationListOutput]{}, err
	}
	kind := coalesce(input.Get("kind"), "user")
	if kind != "user" && kind != "host" {
		return Out[apitypes.SshRevocationListOutput]{}, invalidInput("kind must be 'user' or 'host'")
	}
	kindName := kind.(string)
	settings, err := LoadSshSettings(ctx, server, server.Store, tenantID)
	if err != nil {
		return Out[apitypes.SshRevocationListOutput]{}, err
	}
	version := jsNumber(settings.Get("revocationVersion"))
	cacheKey := tenantID + ":" + kindName
	now := float64(server.Now())
	api.mu.Lock()
	cached, hit := api.cache[cacheKey]
	api.mu.Unlock()
	if hit && cached.version == version && now-cached.at < sshRevocationCacheMs && now >= cached.at {
		return Out[apitypes.SshRevocationListOutput]{Value: cached.value}, nil
	}
	tenant, err := server.Tenant(ctx, server.Store, tenantID)
	if err != nil {
		return Out[apitypes.SshRevocationListOutput]{}, err
	}
	value, err := RevocationList(ctx, server, server.Store, tenant, kindName)
	if err != nil {
		return Out[apitypes.SshRevocationListOutput]{}, err
	}
	api.mu.Lock()
	if len(api.cacheOrder) >= 1000 {
		oldest := api.cacheOrder[0]
		api.cacheOrder = api.cacheOrder[1:]
		delete(api.cache, oldest)
	}
	if _, exists := api.cache[cacheKey]; !exists {
		api.cacheOrder = append(api.cacheOrder, cacheKey)
	}
	api.cache[cacheKey] = sshRevocationEntry{at: now, version: version, value: value}
	api.mu.Unlock()
	return Out[apitypes.SshRevocationListOutput]{Value: value}, nil
}

// RevokeAllCertificates is POST {basePath}/ssh/revokeAllCertificates. Revokes every live user certificate of the
// tenant, after a suspected compromise. Requires iam:ssh:manage.
func (api *SshAPI) RevokeAllCertificates(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshRevokeAllCertificatesInput]) (Out[apitypes.SshRevokeAllCertificatesOutput], error) {
	server := api.server
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshRevokeAllCertificatesOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, sshManage, "ssh/certificates", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		if _, err := AssertSsh(server); err != nil {
			return nil, err
		}
		realmID := jsString(call.Tenant.Get("id"))
		records, err := LiveCertificates(ctx, server, call.Tx, core.NewObject("tenantId", realmID, "kind", "user"))
		if err != nil {
			return nil, err
		}
		revoked, err := api.revokeAll(ctx, call.Tx, realmID, records, "tenant-revoked", jsString(call.Principal.Identity.Get("id")))
		if err != nil {
			return nil, err
		}
		return core.NewObject("revoked", float64(revoked)), nil
	}, false)
	if err != nil {
		return Out[apitypes.SshRevokeAllCertificatesOutput]{}, err
	}
	return Out[apitypes.SshRevokeAllCertificatesOutput]{Value: result}, nil
}

// RevokeCertificate is POST {basePath}/ssh/revokeCertificate. Revokes one certificate: the caller's own without any
// permission (not while viewing as someone nor with a scoped credential; an agent only those of its own session),
// anyone's with iam:ssh:manage. Hosts refuse it from their next revocation list.
func (api *SshAPI) RevokeCertificate(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshRevokeCertificateInput]) (Out[apitypes.SshRevokeCertificateOutput], error) {
	server := api.server
	if _, err := AssertSsh(server); err != nil {
		return Out[apitypes.SshRevokeCertificateOutput]{}, err
	}
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshRevokeCertificateOutput]{}, err
	}
	certificateID, err := Text(input.Get("certificateId"), "certificateId")
	if err != nil {
		return Out[apitypes.SshRevokeCertificateOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.SshRevokeCertificateOutput]{}, err
	}
	found, err := server.Scoped(ctx, server.Store, "sshCertificates", certificateID, tenantID)
	if err != nil {
		return Out[apitypes.SshRevokeCertificateOutput]{}, err
	}
	revoke := func(ctx context.Context, tx core.IamStore, principal *Principal) (*core.Object, error) {
		record, err := server.Scoped(ctx, tx, "sshCertificates", certificateID, tenantID)
		if err != nil {
			return nil, err
		}
		if _, err := api.revokeAll(ctx, tx, tenantID, []*core.Object{record}, "revoked", jsString(principal.Identity.Get("id"))); err != nil {
			return nil, err
		}
		updated, err := server.Scoped(ctx, tx, "sshCertificates", certificateID, tenantID)
		if err != nil {
			return nil, err
		}
		return sshCertificateView(updated, float64(server.Now())), nil
	}
	// The own path skips the permission, so only a session acting in its own unrestricted right takes it (not "view
	// as", not a key or token narrowed by a session policy); an agent acting for the person only for certificates
	// its own session obtained.
	session := authenticated.Session
	if found.Get("identityId") == authenticated.Identity.Get("id") &&
		found.Get("kind") == "user" &&
		!truthy(session.Get("impersonatorId")) &&
		!truthy(session.Get("policy")) &&
		!truthy(session.Get("sourcePolicy")) &&
		(session.Get("kind") != "delegated" || found.Get("sessionId") == session.Get("id")) {
		result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
			principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
			if err != nil {
				return nil, err
			}
			result, err := revoke(ctx, tx, principal)
			if err != nil {
				return nil, err
			}
			if err := server.Events.Audit(ctx, tx, principal, "ssh:certificate:revoke", tenantID, "ssh/certificates/"+certificateID, "allow", false, core.NewObject(
				"reason", "revoked",
				"serial", found.Get("serial"),
				"own", true,
			)); err != nil {
				return nil, err
			}
			return result, nil
		})
		if err != nil {
			return Out[apitypes.SshRevokeCertificateOutput]{}, err
		}
		return Out[apitypes.SshRevokeCertificateOutput]{Value: result}, nil
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, sshManage, "ssh/certificates/"+certificateID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		return revoke(ctx, call.Tx, call.Principal)
	}, false)
	if err != nil {
		return Out[apitypes.SshRevokeCertificateOutput]{}, err
	}
	return Out[apitypes.SshRevokeCertificateOutput]{Value: result}, nil
}

// RevokeIdentity is POST {basePath}/ssh/revokeIdentity. Revokes every live user certificate of one identity, for
// incident response. Requires iam:ssh:manage.
func (api *SshAPI) RevokeIdentity(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshRevokeIdentityInput]) (Out[apitypes.SshRevokeIdentityOutput], error) {
	server := api.server
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshRevokeIdentityOutput]{}, err
	}
	identityID, err := Text(input.Get("identityId"), "identityId")
	if err != nil {
		return Out[apitypes.SshRevokeIdentityOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, sshManage, "ssh/identities/"+identityID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		if _, err := AssertSsh(server); err != nil {
			return nil, err
		}
		realmID := jsString(call.Tenant.Get("id"))
		records, err := LiveCertificates(ctx, server, call.Tx, core.NewObject("tenantId", realmID, "identityId", input.Get("identityId"), "kind", "user"))
		if err != nil {
			return nil, err
		}
		revoked, err := api.revokeAll(ctx, call.Tx, realmID, records, "identity-revoked", jsString(call.Principal.Identity.Get("id")))
		if err != nil {
			return nil, err
		}
		return core.NewObject("revoked", float64(revoked)), nil
	}, false)
	if err != nil {
		return Out[apitypes.SshRevokeIdentityOutput]{}, err
	}
	return Out[apitypes.SshRevokeIdentityOutput]{Value: result}, nil
}

// RotateAuthority is POST {basePath}/ssh/rotateAuthority. Starts rotating the user or host authority. A new pending
// key is published and trusted by hosts and clients from their next sync, and it signs from activateAuthority.
// `activate: true` switches at once (a compromised key; certificates then only work on hosts that already synced).
// Requires iam:ssh:manage.
func (api *SshAPI) RotateAuthority(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshRotateAuthorityInput]) (Out[apitypes.SshRotateAuthorityOutput], error) {
	server := api.server
	kind := input.Get("kind")
	if kind != "user" && kind != "host" {
		return Out[apitypes.SshRotateAuthorityOutput]{}, invalidInput("kind must be 'user' or 'host'")
	}
	kindName := kind.(string)
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshRotateAuthorityOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, sshManage, "ssh/authorities/"+kindName, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		if _, err := AssertSsh(server); err != nil {
			return nil, err
		}
		realmID := jsString(call.Tenant.Get("id"))
		existing, err := TenantAuthorities(ctx, tx, realmID, kindName)
		if err != nil {
			return nil, err
		}
		for _, item := range existing {
			if item.Get("status") == "pending" {
				return nil, core.NewIamError("CONFLICT", "A rotation is already pending; activate or retire it first", 409)
			}
		}
		pending, err := CreateAuthority(ctx, server, tx, realmID, kindName, "pending", jsString(call.Principal.Identity.Get("id")))
		if err != nil {
			return nil, err
		}
		if input.Get("activate") != true {
			return sshPublicAuthority(pending), nil
		}
		activated, err := api.activate(ctx, tx, pending)
		if err != nil {
			return nil, err
		}
		return sshPublicAuthority(activated), nil
	}, false)
	if err != nil {
		return Out[apitypes.SshRotateAuthorityOutput]{}, err
	}
	return Out[apitypes.SshRotateAuthorityOutput]{Value: result}, nil
}

// Setup is POST {basePath}/ssh/setup. Creates the tenant's user authority and host authority when they are missing,
// and returns every authority and the trust material to distribute. Calling it again changes nothing (created is
// empty). Requires iam:ssh:manage.
func (api *SshAPI) Setup(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshSetupInput]) (Out[apitypes.SshSetupOutput], error) {
	server := api.server
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshSetupOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, sshManage, "ssh/authorities", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		if _, err := AssertSsh(server); err != nil {
			return nil, err
		}
		realmID := jsString(call.Tenant.Get("id"))
		ensured, err := EnsureAuthorities(ctx, server, tx, realmID, jsString(call.Principal.Identity.Get("id")))
		if err != nil {
			return nil, err
		}
		authorities, err := TenantAuthorities(ctx, tx, realmID, "")
		if err != nil {
			return nil, err
		}
		trust, err := TrustBundle(ctx, server, tx, call.Tenant, "member")
		if err != nil {
			return nil, err
		}
		return core.NewObject(
			"created", ensured.Get("created"),
			"authorities", sshPublicAuthorities(authorities),
			"trust", trust,
		), nil
	}, false)
	if err != nil {
		return Out[apitypes.SshSetupOutput]{}, err
	}
	return Out[apitypes.SshSetupOutput]{Value: result}, nil
}

// Status is POST {basePath}/ssh/status. The tenant's SSH configuration at a glance: whether it is set up, the
// settings, the authorities that are not retired, hosts by status, counts of live user and host certificates and of
// revoked ones, and the enrolled hosts whose certificate expires within two weeks. Requires iam:ssh:read.
func (api *SshAPI) Status(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshStatusInput]) (Out[apitypes.SshStatusOutput], error) {
	server := api.server
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshStatusOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, sshRead, "ssh/settings", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		options, err := AssertSsh(server)
		if err != nil {
			return nil, err
		}
		realmID := jsString(call.Tenant.Get("id"))
		authorities, err := TenantAuthorities(ctx, tx, realmID, "")
		if err != nil {
			return nil, err
		}
		hosts, err := tx.Find(ctx, "sshHosts", core.NewObject("tenantId", realmID), nil)
		if err != nil {
			return nil, err
		}
		now := float64(server.Now())
		records, err := tx.Find(ctx, "sshCertificates", core.NewObject("tenantId", realmID), nil)
		if err != nil {
			return nil, err
		}
		count := func(status string) float64 {
			total := 0.0
			for _, host := range hosts {
				if host.Get("status") == status {
					total++
				}
			}
			return total
		}
		configured := false
		visible := []*core.Object{}
		for _, item := range authorities {
			if item.Get("kind") == "user" && item.Get("status") == "active" {
				configured = true
			}
			if item.Get("status") != "retired" {
				visible = append(visible, item)
			}
		}
		settings, err := LoadSshSettings(ctx, server, tx, realmID)
		if err != nil {
			return nil, err
		}
		activeUser, activeHost, revoked := 0.0, 0.0, 0.0
		for _, record := range records {
			if !(jsNumber(record.Get("validBefore")) > now) {
				continue
			}
			live := isUndefined(record.Get("revokedAt"))
			switch {
			case record.Get("kind") == "user" && live:
				activeUser++
			case record.Get("kind") == "host" && live:
				activeHost++
			}
			if !live {
				revoked++
			}
		}
		expiringSoon := 0.0
		for _, host := range hosts {
			if host.Get("status") == "enrolled" && jsNumber(coalesce(host.Get("certificateExpiresAt"), 0.0)) < now+14*86_400_000 {
				expiringSoon++
			}
		}
		return core.NewObject(
			"configured", configured,
			"settings", sshSettingsView(settings, options),
			"authorities", sshPublicAuthorities(visible),
			"hosts", core.NewObject("pending", count("pending"), "enrolled", count("enrolled"), "disabled", count("disabled")),
			"certificates", core.NewObject("activeUser", activeUser, "activeHost", activeHost, "revoked", revoked),
			"hostsExpiringSoon", expiringSoon,
		), nil
	}, false)
	if err != nil {
		return Out[apitypes.SshStatusOutput]{}, err
	}
	return Out[apitypes.SshStatusOutput]{Value: result}, nil
}

// Sweep is POST {basePath}/ssh/sweep. Runs the continuous-authorization sweep for this tenant now (the scheduler job
// covers every tenant). Requires iam:ssh:manage.
func (api *SshAPI) Sweep(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshSweepInput]) (Out[apitypes.SshSweepOutput], error) {
	server := api.server
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshSweepOutput]{}, err
	}
	// Authorized (and audited) first; the sweep then runs in its own short transactions.
	if _, err := Operate(ctx, server.Operations, credential, tenantID, sshManage, "ssh/certificates", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		return AssertSsh(server)
	}, false); err != nil {
		return Out[apitypes.SshSweepOutput]{}, err
	}
	result, err := SweepSshCertificates(ctx, server, core.NewObject("tenantId", tenantID))
	if err != nil {
		return Out[apitypes.SshSweepOutput]{}, err
	}
	return Out[apitypes.SshSweepOutput]{Value: result}, nil
}

// SyncHost is POST {basePath}/ssh/syncHost (public: no request credential). A host's periodic check-in with its
// renewal token: returns the current trust, principals files and revocation list, and a new host certificate (with a
// new renewal token) when its addresses or the host authority changed or the current one is past two thirds of its
// lifetime; `renew: true` forces one at most hourly. `publicKey`, when sent, must be the enrolled key
// (`HOST_KEY_CHANGED` otherwise: re-enroll). While the organization is suspended a host still syncs (its revocation
// list then revokes every user certificate) but gets no new certificate.
func (api *SshAPI) SyncHost(ctx context.Context, input In[apitypes.SshSyncHostInput]) (Out[apitypes.SshSyncHostOutput], error) {
	server := api.server
	options, err := AssertSsh(server)
	if err != nil {
		return Out[apitypes.SshSyncHostOutput]{}, err
	}
	renewalInput := input.Get("renewalToken")
	hostID, err := sshTokenHost(renewalInput, "biam_sshr")
	if err != nil {
		return Out[apitypes.SshSyncHostOutput]{}, err
	}
	known, err := server.Store.Get(ctx, "sshHosts", hostID)
	if err != nil {
		return Out[apitypes.SshSyncHostOutput]{}, err
	}
	if known != nil {
		limit := int64(120)
		if err := server.Auth.LimitAttempt(ctx, jsString(known.Get("tenantId")), "ssh:sync:"+hostID, auth.LimitAttemptOptions{Limit: &limit}); err != nil {
			return Out[apitypes.SshSyncHostOutput]{}, err
		}
	}
	var offered *core.Object
	if value := input.Get("publicKey"); !isUndefined(value) {
		if offered, err = ParseSshPublicKey(value, nil); err != nil {
			return Out[apitypes.SshSyncHostOutput]{}, err
		}
	}
	renew := input.Get("renew") == true
	outcome, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (sshHostOutcome, error) {
		host, err := tx.Get(ctx, "sshHosts", hostID)
		if err != nil {
			return sshHostOutcome{}, err
		}
		presented := Hash(jsString(renewalInput))
		current := host != nil && truthy(host.Get("renewalTokenHash")) && SameHash(host.Get("renewalTokenHash"), presented)
		previous := host != nil && truthy(host.Get("previousRenewalTokenHash")) && SameHash(host.Get("previousRenewalTokenHash"), presented)
		if host == nil || host.Get("status") != "enrolled" || (!current && !previous) {
			return sshHostOutcome{refusal: sshInvalidToken(), host: host}, nil
		}
		tenantID := jsString(host.Get("tenantId"))
		tenant, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return sshHostOutcome{}, err
		}
		active, err := TenantActive(ctx, server, tx, tenant)
		if err != nil {
			return sshHostOutcome{}, err
		}
		key, err := StoredHostKey(host)
		if err != nil {
			return sshHostOutcome{}, err
		}
		// The renewal token never moves the host's identity to another key: a stolen token must not yield a host
		// certificate for an attacker's key. A rebuilt host re-enrolls with a new join token.
		if offered != nil && offered.Get("fingerprint") != key.Get("fingerprint") {
			return sshHostOutcome{
				refusal: core.NewIamError("HOST_KEY_CHANGED",
					"This host key differs from the enrolled one; re-enroll the host with a new join token", 409),
				host:     host,
				metadata: core.NewObject("offered", offered.Get("fingerprint")),
			}, nil
		}
		var certificate *core.Object
		if certificateID := host.Get("certificateId"); truthy(certificateID) {
			if certificate, err = tx.Get(ctx, "sshCertificates", jsString(certificateID)); err != nil {
				return sshHostOutcome{}, err
			}
		}
		now := float64(server.Now())
		principals := newOrderedSet(append([]string{jsString(host.Get("name"))}, sshStrings(host.Get("addresses"))...)...).Values()
		var hostAuthority *core.Object
		if active {
			if hostAuthority, err = ActiveAuthority(ctx, tx, tenantID, "host"); err != nil {
				return sshHostOutcome{}, err
			}
		}
		stale := certificate == nil
		if !stale {
			validAfter, validBefore := jsNumber(certificate.Get("validAfter")), jsNumber(certificate.Get("validBefore"))
			stale = !isUndefined(certificate.Get("revokedAt")) ||
				certificate.Get("publicKeyFingerprint") != key.Get("fingerprint") ||
				(hostAuthority != nil && certificate.Get("authorityId") != hostAuthority.Get("id")) ||
				!sshSameList(certificate.Get("principals"), stringsOf(principals)) ||
				now >= validAfter+((validBefore-validAfter)*2)/3
		}
		forced := renew && (certificate == nil || now-jsNumber(certificate.Get("issuedAt")) >= sshForcedRenewalMs)
		line := ""
		if certificate != nil {
			if text, ok := certificate.Get("certificate").(string); ok {
				line = text
			}
		}
		issued := certificate
		renewed := active && (forced || stale || line == "")
		renewal := ""
		if renewed {
			record, nextLine, err := api.certifyHost(ctx, tx, host, key, options)
			if err != nil {
				return sshHostOutcome{}, err
			}
			line, issued = nextLine, record
			renewal = sshRenewalToken(jsString(host.Get("id")))
		}
		if issued == nil {
			return sshHostOutcome{}, errors.New("Cannot read properties of undefined (reading 'id')")
		}
		changes := core.NewObject(
			"certificateId", issued.Get("id"),
			"certificateExpiresAt", issued.Get("validBefore"),
		)
		// A new token rotates in; the one presented stays valid until the new one is used. Using the new one retires
		// the old for good.
		if renewal != "" {
			changes.Set("renewalTokenHash", Hash(renewal))
			if current {
				changes.Set("previousRenewalTokenHash", host.Get("renewalTokenHash"))
			} else {
				changes.Set("previousRenewalTokenHash", host.Get("previousRenewalTokenHash"))
			}
		} else if current && truthy(host.Get("previousRenewalTokenHash")) {
			changes.Set("previousRenewalTokenHash", core.Undefined)
		}
		if renewed {
			changes.Set("renewedAt", now)
		}
		changes.Set("lastSeenAt", now)
		if renewed {
			changes.Set("updatedAt", now)
		} else {
			changes.Set("updatedAt", host.Get("updatedAt"))
		}
		saved, err := tx.Put(ctx, "sshHosts", host.Spread(changes))
		if err != nil {
			return sshHostOutcome{}, err
		}
		if renewed {
			if err := api.hostAudit(ctx, tx, saved, "ssh:host:renew", core.NewObject(
				"serial", issued.Get("serial"),
				"fingerprint", key.Get("fingerprint"),
			)); err != nil {
				return sshHostOutcome{}, err
			}
		}
		setup, err := api.hostSetup(ctx, tx, tenant, saved, line, jsNumber(issued.Get("validBefore")), renewed, renewal)
		if err != nil {
			return sshHostOutcome{}, err
		}
		return sshHostOutcome{value: setup}, nil
	})
	if err != nil {
		return Out[apitypes.SshSyncHostOutput]{}, err
	}
	if outcome.refusal != nil {
		return Out[apitypes.SshSyncHostOutput]{}, api.refuseHost(ctx, outcome.host, "ssh:host:sync", outcome.refusal, outcome.metadata)
	}
	return Out[apitypes.SshSyncHostOutput]{Value: outcome.value}, nil
}

// Trust is POST {basePath}/ssh/trust (public: no request credential). The tenant's public trust: user authority keys
// for hosts (trustedUserCaKeys for TrustedUserCAKeys), host authority keys, and the @cert-authority knownhosts line
// only when hostPatterns is set. Members get the line for the enrolled names from `clientTrust`.
func (api *SshAPI) Trust(ctx context.Context, input In[apitypes.SshTrustInput]) (Out[apitypes.SshTrustOutput], error) {
	server := api.server
	if _, err := AssertSsh(server); err != nil {
		return Out[apitypes.SshTrustOutput]{}, err
	}
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshTrustOutput]{}, err
	}
	tenant, err := server.Tenant(ctx, server.Store, tenantID)
	if err != nil {
		return Out[apitypes.SshTrustOutput]{}, err
	}
	result, err := TrustBundle(ctx, server, server.Store, tenant, "public")
	if err != nil {
		return Out[apitypes.SshTrustOutput]{}, err
	}
	return Out[apitypes.SshTrustOutput]{Value: result}, nil
}

// UpdateHost is POST {basePath}/ssh/updateHost. Changes a host's addresses, logins, labels or description (null
// clears it). New addresses follow the `createHost` rules; a removed address revokes the host's certificate at once
// (the host gets a new one at its next `syncHost`), and new logins reach the principals files then too. Requires
// iam:ssh:manage.
func (api *SshAPI) UpdateHost(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshUpdateHostInput]) (Out[apitypes.SshUpdateHostOutput], error) {
	server := api.server
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshUpdateHostOutput]{}, err
	}
	name, err := api.hostRecordName(ctx, tenantID, input.Get("hostId"))
	if err != nil {
		return Out[apitypes.SshUpdateHostOutput]{}, err
	}
	changes := core.NewObject()
	if value := input.Get("logins"); !isUndefined(value) {
		logins, err := sshHostLogins(value)
		if err != nil {
			return Out[apitypes.SshUpdateHostOutput]{}, err
		}
		changes.Set("logins", stringsOf(logins))
	}
	if value := input.Get("addresses"); !isUndefined(value) {
		addresses, err := sshHostAddresses(value)
		if err != nil {
			return Out[apitypes.SshUpdateHostOutput]{}, err
		}
		changes.Set("addresses", stringsOf(sshWithout(addresses, name)))
	}
	if value := input.Get("labels"); !isUndefined(value) {
		labels, err := SshLabels(value)
		if err != nil {
			return Out[apitypes.SshUpdateHostOutput]{}, err
		}
		changes.Set("labels", labels)
	}
	resourceID := "ssh/hosts/" + name
	result, err := sshAudited(ctx, api, credential, tenantID, resourceID, func() (*core.Object, error) {
		return Operate(ctx, server.Operations, credential, tenantID, sshManage, resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, principal := call.Tx, call.Principal
			if _, err := AssertSsh(server); err != nil {
				return nil, err
			}
			host, err := api.scopedHost(ctx, tx, tenantID, input.Get("hostId"))
			if err != nil {
				return nil, err
			}
			next := host.Spread(changes, core.NewObject("updatedAt", float64(server.Now())))
			if description := input.Get("description"); description == nil {
				next.Delete("description")
			} else if !isUndefined(description) {
				text, err := Text(description, "description", 512)
				if err != nil {
					return nil, err
				}
				next.Set("description", text)
			}
			before := sshStrings(host.Get("addresses"))
			after := sshStrings(next.Get("addresses"))
			added := sshMissing(after, before)
			removed := sshMissing(before, after)
			hostID := jsString(host.Get("id"))
			if len(added) > 0 {
				if err := api.assertNamesAllowed(ctx, tx, principal, tenantID, append([]string{jsString(host.Get("name"))}, added...), hostID); err != nil {
					return nil, err
				}
			}
			// A name the host gives up could be claimed by another host: its certificate must stop vouching for it.
			if len(removed) > 0 {
				live, err := LiveCertificates(ctx, server, tx, core.NewObject("tenantId", tenantID, "hostId", hostID))
				if err != nil {
					return nil, err
				}
				if _, err := api.revokeAll(ctx, tx, tenantID, live, "addresses-changed", jsString(principal.Identity.Get("id"))); err != nil {
					return nil, err
				}
			}
			saved, err := tx.Put(ctx, "sshHosts", next)
			if err != nil {
				return nil, err
			}
			return core.NewObject(
				"host", sshPublicHost(saved),
				"syncRequired", !sshSameList(host.Get("logins"), saved.Get("logins")) || len(added) > 0 || len(removed) > 0,
			), nil
		}, false)
	})
	if err != nil {
		return Out[apitypes.SshUpdateHostOutput]{}, err
	}
	return Out[apitypes.SshUpdateHostOutput]{Value: result}, nil
}

// UpdateSettings is POST {basePath}/ssh/updateSettings. Changes the tenant's settings; fields left out keep their
// values. hostPatterns are knownhosts patterns (* and ? globs, ! negation) that must pin a verified domain of the
// organization or an address prefix, and cover every host already enrolled. Requires iam:ssh:manage.
func (api *SshAPI) UpdateSettings(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshUpdateSettingsInput]) (Out[apitypes.SshUpdateSettingsOutput], error) {
	server := api.server
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshUpdateSettingsOutput]{}, err
	}
	result, err := sshAudited(ctx, api, credential, tenantID, "ssh/settings", func() (*core.Object, error) {
		return Operate(ctx, server.Operations, credential, tenantID, sshManage, "ssh/settings", func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx := call.Tx
			options, err := AssertSsh(server)
			if err != nil {
				return nil, err
			}
			realmID := jsString(call.Tenant.Get("id"))
			current, err := LoadSshSettings(ctx, server, tx, realmID)
			if err != nil {
				return nil, err
			}
			next := current.Spread()
			for _, key := range []string{"requireMfa", "requireSecurityKey", "requireUserVerification", "bindSourceAddress"} {
				value := input.Get(key)
				if isUndefined(value) {
					continue
				}
				flag, ok := value.(bool)
				if !ok {
					return nil, invalidInput(key + " must be a boolean")
				}
				next.Set(key, flag)
			}
			maxUser := jsNumber(options.Get("maxUserCertificateMs"))
			if value := input.Get("maxCertificateMs"); !isUndefined(value) {
				number, err := Integer(value, "maxCertificateMs", 60_000, maxUser)
				if err != nil {
					return nil, err
				}
				next.Set("maxCertificateMs", number)
			}
			if value := input.Get("defaultCertificateMs"); !isUndefined(value) {
				number, err := Integer(value, "defaultCertificateMs", 60_000, maxUser)
				if err != nil {
					return nil, err
				}
				next.Set("defaultCertificateMs", number)
			}
			if jsNumber(next.Get("defaultCertificateMs")) > jsNumber(next.Get("maxCertificateMs")) {
				return nil, invalidInput("defaultCertificateMs cannot exceed maxCertificateMs")
			}
			if value := input.Get("hostPatterns"); !isUndefined(value) {
				domains, err := VerifiedDomains(ctx, tx, realmID)
				if err != nil {
					return nil, err
				}
				patterns, err := HostPatternList(value, domains)
				if err != nil {
					return nil, err
				}
				next.Set("hostPatterns", stringsOf(patterns))
				// Every host the authority already vouches for must stay inside the new patterns.
				hosts, err := tx.Find(ctx, "sshHosts", core.NewObject("tenantId", realmID), nil)
				if err != nil {
					return nil, err
				}
				for _, host := range hosts {
					if host.Get("status") == "disabled" {
						continue
					}
					names := append([]string{jsString(host.Get("name"))}, sshStrings(host.Get("addresses"))...)
					if err := AssertVouchable(next, domains, names); err != nil {
						return nil, err
					}
				}
			}
			next.Set("updatedAt", float64(server.Now()))
			next.Set("updatedBy", call.Principal.Identity.Get("id"))
			if _, err := SaveSshSettings(ctx, tx, next); err != nil {
				return nil, err
			}
			return sshSettingsView(next, options), nil
		}, false)
	})
	if err != nil {
		return Out[apitypes.SshUpdateSettingsOutput]{}, err
	}
	return Out[apitypes.SshUpdateSettingsOutput]{Value: result}, nil
}

// WhoCanLogin is POST {basePath}/ssh/whoCanLogin. Access review: which active identities may log in to a host, and
// as which logins. Each identity is decided in a synthetic session (with MFA when assumeMfa), optionally for one
// login or kind. Requires iam:ssh:read.
func (api *SshAPI) WhoCanLogin(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshWhoCanLoginInput]) (Out[apitypes.SshWhoCanLoginOutput], error) {
	server := api.server
	tenantID, err := sshTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.SshWhoCanLoginOutput]{}, err
	}
	name, err := api.hostRecordName(ctx, tenantID, input.Get("hostId"))
	if err != nil {
		return Out[apitypes.SshWhoCanLoginOutput]{}, err
	}
	only := ""
	if value := input.Get("login"); !isUndefined(value) {
		if only, err = SshLogin(value); err != nil {
			return Out[apitypes.SshWhoCanLoginOutput]{}, err
		}
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, sshRead, "ssh/hosts/"+name, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		if _, err := AssertSsh(server); err != nil {
			return nil, err
		}
		host, err := api.scopedHost(ctx, tx, tenantID, input.Get("hostId"))
		if err != nil {
			return nil, err
		}
		logins := sshStrings(host.Get("logins"))
		if only != "" {
			logins = []string{}
			for _, login := range sshStrings(host.Get("logins")) {
				if login == only {
					logins = append(logins, login)
				}
			}
		}
		filter := core.NewObject("tenantId", tenantID, "status", "active")
		if kind := input.Get("kind"); !isUndefined(kind) {
			filter.Set("kind", kind)
		}
		identities, err := tx.Find(ctx, "identities", filter, nil)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(identities, func(i, j int) bool { return ByID(identities[i], identities[j]) < 0 })
		labeled, err := api.classifiedHosts(ctx, tx, tenantID, []*core.Object{host})
		if err != nil {
			return nil, err
		}
		assumeMfa := input.Get("assumeMfa") == true
		entries := []any{}
		for _, identity := range identities {
			if server.IdentityExpired(identity) {
				continue
			}
			prepared, err := server.Decisions.PrepareDecision(ctx, tx, server.Decisions.SimulatedPrincipal(identity, assumeMfa), call.Tenant, SshLoginAction)
			if err != nil {
				return nil, err
			}
			allowed := []string{}
			for _, login := range logins {
				resource, err := LoginResource(host, login)
				if err != nil {
					return nil, err
				}
				decision, err := DecideOn(prepared, labeled(resource), SshLoginAction)
				if err != nil {
					return nil, err
				}
				if decision.Allowed {
					allowed = append(allowed, login)
				}
			}
			if len(allowed) == 0 {
				continue
			}
			entry := core.NewObject("identityId", identity.Get("id"))
			if value := identity.Get("name"); truthy(value) {
				entry.Set("name", value)
			}
			if value := identity.Get("email"); truthy(value) {
				entry.Set("email", value)
			}
			entry.Set("kind", identity.Get("kind"))
			entry.Set("logins", stringsOf(allowed))
			entries = append(entries, entry)
		}
		return core.NewObject("host", host.Get("name"), "identities", entries), nil
	}, false)
	if err != nil {
		return Out[apitypes.SshWhoCanLoginOutput]{}, err
	}
	return Out[apitypes.SshWhoCanLoginOutput]{Value: result}, nil
}

// SshRuntime is api/ssh.ts createSshRuntime(): `iam.ssh`, the deployment-side jobs and public reads (no credential),
// for schedulers and custom routes.
type SshRuntime struct {
	server *ServerContext
	// Enabled Whether the `ssh` option is on.
	Enabled bool
}

// Sweep (api/ssh.ts createSshRuntime().sweep): Continuous authorization: revokes live certificates whose holder,
// session or access went away (run every few minutes). input may hold tenantId (nil: every tenant).
func (s *SshRuntime) Sweep(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	return SweepSshCertificates(ctx, s.server, input)
}

// RevocationList (api/ssh.ts createSshRuntime().revocationList): A tenant's KRL as bytes, for serving it from a
// custom route (`application/octet-stream`): the revocation list with `bytes` ([]byte) added. kind "" is user.
func (s *SshRuntime) RevocationList(ctx context.Context, tenantID string, kind string) (result *core.Object, err error) {
	if kind == "" {
		kind = "user"
	}
	server := s.server
	if _, err := AssertSsh(server); err != nil {
		return nil, err
	}
	tenant, err := server.Tenant(ctx, server.Store, tenantID)
	if err != nil {
		return nil, err
	}
	list, err := RevocationList(ctx, server, server.Store, tenant, kind)
	if err != nil {
		return nil, err
	}
	result = list.Spread()
	result.SetRaw("bytes", nodeBase64Decode(jsString(list.Get("krl"))))
	return result, nil
}

// CreateSshRuntime builds the SshRuntime (api/ssh.ts createSshRuntime).
func CreateSshRuntime(server *ServerContext) *SshRuntime {
	_, err := AssertSsh(server)
	return &SshRuntime{server: server, Enabled: err == nil}
}
