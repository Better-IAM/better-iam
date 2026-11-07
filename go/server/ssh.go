package server

// Skeleton of packages/server/src/ssh.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// ActiveAuthority (ssh.ts activeAuthority): The active authority of a kind, or SSH_NOT_CONFIGURED.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ActiveAuthority(ctx context.Context, tx core.IamStore, tenantID string, kind string) (result *core.Object, err error) {
	err = notImplemented("ssh.ts activeAuthority")
	return
}

// AssertHostKeyFree (ssh.ts assertHostKeyFree): Refuses a host key that is a tenant authority key or another host's
// key (a revocation of it would hit them).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AssertHostKeyFree(ctx context.Context, tx core.IamStore, tenantID string, hostID string, key *core.Object) (err error) {
	err = notImplemented("ssh.ts assertHostKeyFree")
	return
}

// AssertNamesFree (ssh.ts assertNamesFree): Refuses names or addresses another host of the tenant already uses (any
// status).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AssertNamesFree(ctx context.Context, tx core.IamStore, tenantID string, names []string, hostID string) (err error) {
	err = notImplemented("ssh.ts assertNamesFree")
	return
}

// AssertSsh (ssh.ts assertSsh): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AssertSsh(server *ServerContext) (result *core.Object, err error) {
	err = notImplemented("ssh.ts assertSsh")
	return
}

// AssertVouchable (ssh.ts assertVouchable): Refuses host names or addresses the organization cannot vouch for:
// outside its `hostPatterns` when it has any; otherwise anything but single labels, private addresses, and names
// under its verified domains.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AssertVouchable(settings *core.Object, domains []string, names []string) (err error) {
	err = notImplemented("ssh.ts assertVouchable")
	return
}

// BumpRevocationVersion (ssh.ts bumpRevocationVersion): Bumps the revocation list version after a revocation.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func BumpRevocationVersion(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string) (err error) {
	err = notImplemented("ssh.ts bumpRevocationVersion")
	return
}

// CertificateKeyID (ssh.ts certificateKeyId): A key ID for sshd logs: who (and the agent acting for them), printable
// ASCII only.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CertificateKeyID(principal *Principal) (result string, err error) {
	err = notImplemented("ssh.ts certificateKeyId")
	return
}

// CreateAuthority (ssh.ts createAuthority): Creates an authority key, sealed under the deployment secret.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CreateAuthority(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, kind string, status string, actorID string) (result *core.Object, err error) {
	err = notImplemented("ssh.ts createAuthority")
	return
}

// EnsureAuthorities (ssh.ts ensureAuthorities): Creates the tenant's user and host authorities when missing; returns
// the active ones.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func EnsureAuthorities(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, actorID string) (result *core.Object, err error) {
	err = notImplemented("ssh.ts ensureAuthorities")
	return
}

// HostByName (ssh.ts hostByName): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func HostByName(ctx context.Context, tx core.IamStore, tenantID string, name string) (result *core.Object, err error) {
	err = notImplemented("ssh.ts hostByName")
	return
}

// HostPatternList (ssh.ts hostPatternList): Validates `hostPatterns`: every positive pattern must pin a literal
// suffix the organization owns (a verified domain such as `*.corp.example.com`) or a literal address prefix
// (`10.20.*`, `fd00:1:*`); `*` alone is refused.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func HostPatternList(value any, domains []string) (result []string, err error) {
	err = notImplemented("ssh.ts hostPatternList")
	return
}

// HostResource (ssh.ts hostResource): What policies see for `ssh-host/{host}`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func HostResource(host *core.Object) (result ResolvedResource, err error) {
	err = notImplemented("ssh.ts hostResource")
	return
}

// LiveCertificates (ssh.ts liveCertificates): Certificate records that are still valid and not revoked.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LiveCertificates(ctx context.Context, server *ServerContext, tx core.IamStore, filter *core.Object) (result []*core.Object, err error) {
	err = notImplemented("ssh.ts liveCertificates")
	return
}

// LoadSshSettings (ssh.ts loadSshSettings): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LoadSshSettings(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string) (result *core.Object, err error) {
	err = notImplemented("ssh.ts loadSshSettings")
	return
}

// LoginResource (ssh.ts loginResource): What policies see for `ssh-login/{host}/{login}`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LoginResource(host *core.Object, login string) (result ResolvedResource, err error) {
	err = notImplemented("ssh.ts loginResource")
	return
}

// MarkRevoked (ssh.ts markRevoked): Marks one certificate revoked (idempotent); the caller bumps the revocation
// version.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func MarkRevoked(ctx context.Context, server *ServerContext, tx core.IamStore, record *core.Object, reason string, actorID string) (result *core.Object, err error) {
	err = notImplemented("ssh.ts markRevoked")
	return
}

// OpenAuthority (ssh.ts openAuthority): Opens an authority's signing key.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func OpenAuthority(server *ServerContext, authority *core.Object) (result *core.Object, err error) {
	err = notImplemented("ssh.ts openAuthority")
	return
}

// PrincipalFiles (ssh.ts principalFiles): The per-host principals file lines: one file per login holding
// `{login}@{host}`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PrincipalFiles(host *core.Object) (result *core.Object, err error) {
	err = notImplemented("ssh.ts principalFiles")
	return
}

// ResolveSshResource (ssh.ts resolveSshResource): resolves `ssh-login/{host}/{login}` and `ssh-host/{host}` for the
// decision engine; nil for other types or when the SSH module is off.
//
// PARTIAL: the guard is ported; the host lookup is a stub.
func ResolveSshResource(ctx context.Context, server *ServerContext, tx core.IamStore, reference core.ResourceRef) (*ResolvedResource, error) {
	if reference.Type != SshLoginResourceType && reference.Type != SshHostResourceType {
		return nil, nil
	}
	if !server.Options.Ssh.IsOn() {
		return nil, nil
	}
	return nil, notImplemented("ssh.ts resolveSshResource")
}

// RevocationList (ssh.ts revocationList): A tenant's binary key revocation list. - `user` (sshd `RevokedKeys`): the
// serials of unexpired user certificates that were revoked, whose holder is no longer active or whose session is
// gone (even before the sweep marks them), or all of them while the tenant or an ancestor is suspended. - `host`
// (ssh `RevokedHostKeys` on clients): revoked host certificate serials and host keys clients must refuse.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RevocationList(ctx context.Context, server *ServerContext, reader core.IamStore, tenant *core.Object, kind string) (result *core.Object, err error) {
	err = notImplemented("ssh.ts revocationList")
	return
}

// SaveSshSettings (ssh.ts saveSshSettings): Stores a tenant's settings (the record exists once anything was changed
// or revoked).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SaveSshSettings(ctx context.Context, tx core.IamStore, settings *core.Object) (result *core.Object, err error) {
	err = notImplemented("ssh.ts saveSshSettings")
	return
}

// SshHostName (ssh.ts sshHostName): Host names: lowercase letters, digits, dots and hyphens (no `/`, `@` or
// wildcards, so they can sit in principals).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SshHostName(value any) (result string, err error) {
	err = notImplemented("ssh.ts sshHostName")
	return
}

// SshLabels (ssh.ts sshLabels): Host labels: at most 32 `name: value` pairs; the names policies read as
// `resource.{name}`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SshLabels(value any) (result *core.Object, err error) {
	err = notImplemented("ssh.ts sshLabels")
	return
}

// SshPlugins (ssh.ts sshPlugins): the catalog entries the module contributes when enabled (the `ssh-login` and
// `ssh-host` types and their actions); none when it is off.
//
// STUB: returns NOT_IMPLEMENTED when the SSH module is enabled, until the module is ported.
func SshPlugins(options *BetterIamOptions) (result []*core.IamPlugin, err error) {
	if !options.Ssh.IsOn() {
		return nil, nil
	}
	err = notImplemented("ssh.ts sshPlugins")
	return
}

// StoredHostKey (ssh.ts storedHostKey): Parses a stored host key line (enrolled keys were validated when they
// arrived).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func StoredHostKey(host *core.Object) (result *core.Object, err error) {
	err = notImplemented("ssh.ts storedHostKey")
	return
}

// SweepSshCertificates (ssh.ts sweepSshCertificates): Continuous authorization for certificates already issued:
// revokes live user certificates whose holder is no longer active, whose issuing session (user session, API key,
// role session, session token or delegated session) was revoked, ended or no longer validates, or whose hosts,
// logins and forwarding policies no longer allow as decided for that very session. A scheduler job
// (`iam.ssh.sweep`); hosts pick the result up with their next revocation list.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SweepSshCertificates(ctx context.Context, server *ServerContext, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("ssh.ts sweepSshCertificates")
	return
}

// TenantActive (ssh.ts tenantActive): Whether the tenant and every ancestor are active.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TenantActive(ctx context.Context, server *ServerContext, reader core.IamStore, tenant *core.Object) (result bool, err error) {
	err = notImplemented("ssh.ts tenantActive")
	return
}

// TenantAuthorities (ssh.ts tenantAuthorities): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TenantAuthorities(ctx context.Context, tx core.IamStore, tenantID string, kind string) (result []*core.Object, err error) {
	err = notImplemented("ssh.ts tenantAuthorities")
	return
}

// TrustBundle (ssh.ts trustBundle): Trust material. `public` (anyone with the tenant ID): the authority keys, and a
// known_hosts line only for configured `hostPatterns`. `member` (members and hosts): the known_hosts line for the
// enrolled names as well, and `@revoked` lines for host keys clients must refuse.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TrustBundle(ctx context.Context, server *ServerContext, reader core.IamStore, tenant *core.Object, audience string) (result *core.Object, err error) {
	err = notImplemented("ssh.ts trustBundle")
	return
}

// VerifiedDomains (ssh.ts verifiedDomains): The tenant's verified email/DNS domains (domains API), which bound the
// host names it may vouch for.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func VerifiedDomains(ctx context.Context, tx core.IamStore, tenantID string) (result []string, err error) {
	err = notImplemented("ssh.ts verifiedDomains")
	return
}

// DelegatedCertificateMs is ssh.ts DELEGATED_CERTIFICATE_MS.
const DelegatedCertificateMs = 600000

// SshForwardingActions is ssh.ts sshForwardingActions.
var SshForwardingActions = mustObject(`{"ssh:port-forward":"permit-port-forwarding","ssh:agent-forward":"permit-agent-forwarding","ssh:x11-forward":"permit-X11-forwarding"}`)

// SshLoginAction is ssh.ts sshLoginAction.
const SshLoginAction = "ssh:login"

// SshLoginResourceType and SshHostResourceType are the SSH resource types (ssh.ts).
const (
	SshLoginResourceType = "ssh-login"
	SshHostResourceType  = "ssh-host"
)
