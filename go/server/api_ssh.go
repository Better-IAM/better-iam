package server

// Skeleton of packages/server/src/api/ssh.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// SshAPI is the `ssh` API group (packages/server/src/api/ssh.ts createSshApi): every method runs through the
// operation envelope; the router maps POST {basePath}/ssh/{method} onto it.
type SshAPI struct {
	server *ServerContext
}

// CreateSshAPI builds the `ssh` API group.
func CreateSshAPI(server *ServerContext) *SshAPI {
	return &SshAPI{server: server}
}

// ActivateAuthority is POST {basePath}/ssh/activateAuthority. Makes a pending authority the signing key. The key it replaces stays trusted as previous, so certificates it issued keep working until they expire.
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) ActivateAuthority(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshActivateAuthorityInput]) (Out[apitypes.SshActivateAuthorityOutput], error) {
	return Out[apitypes.SshActivateAuthorityOutput]{}, notImplemented("ssh.activateAuthority")
}

// ClientTrust is POST {basePath}/ssh/clientTrust. What a member's SSH client needs: knownhosts lines trusting the host authority for the organization's enrolled names (or its patterns), @revoked lines for host keys to refuse, and the host revocation…
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) ClientTrust(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshClientTrustInput]) (Out[apitypes.SshClientTrustOutput], error) {
	return Out[apitypes.SshClientTrustOutput]{}, notImplemented("ssh.clientTrust")
}

// CreateHost is POST {basePath}/ssh/createHost. Registers a server: its name (unique, lowercase letters, digits, .
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) CreateHost(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshCreateHostInput]) (Out[apitypes.SshCreateHostOutput], error) {
	return Out[apitypes.SshCreateHostOutput]{}, notImplemented("ssh.createHost")
}

// DeleteHost is POST {basePath}/ssh/deleteHost. Deletes a host and revokes its certificate. Certificates naming it open nothing afterwards.
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) DeleteHost(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshDeleteHostInput]) (Out[apitypes.SshDeleteHostOutput], error) {
	return Out[apitypes.SshDeleteHostOutput]{}, notImplemented("ssh.deleteHost")
}

// DisableHost is POST {basePath}/ssh/disableHost. Takes a host out of service.
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) DisableHost(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshDisableHostInput]) (Out[apitypes.SshDisableHostOutput], error) {
	return Out[apitypes.SshDisableHostOutput]{}, notImplemented("ssh.disableHost")
}

// EnrollHost is POST {basePath}/ssh/enrollHost (public: no request credential). A server enrolls with its join token and public host key (not a security key).
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) EnrollHost(ctx context.Context, input In[apitypes.SshEnrollHostInput]) (Out[apitypes.SshEnrollHostOutput], error) {
	return Out[apitypes.SshEnrollHostOutput]{}, notImplemented("ssh.enrollHost")
}

// GetCertificate is POST {basePath}/ssh/getCertificate. One certificate record: kind, serial, key ID, principals, hosts and logins, extensions, key fingerprint, validity, and revocation details.
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) GetCertificate(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshGetCertificateInput]) (Out[apitypes.SshGetCertificateOutput], error) {
	return Out[apitypes.SshGetCertificateOutput]{}, notImplemented("ssh.getCertificate")
}

// GetHost is POST {basePath}/ssh/getHost. One host: status, addresses, logins, labels, host key fingerprint, certificate expiry and when it last synced. Token hashes never appear.
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) GetHost(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshGetHostInput]) (Out[apitypes.SshGetHostOutput], error) {
	return Out[apitypes.SshGetHostOutput]{}, notImplemented("ssh.getHost")
}

// GetSettings is POST {basePath}/ssh/getSettings. The tenant's settings (MFA, security keys, source-address binding, default and maximum lifetimes, host patterns), the revocation list version, and the deployment's ceiling for maxCertificateMs.
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) GetSettings(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshGetSettingsInput]) (Out[apitypes.SshGetSettingsOutput], error) {
	return Out[apitypes.SshGetSettingsOutput]{}, notImplemented("ssh.getSettings")
}

// IssueCertificate is POST {basePath}/ssh/issueCertificate. Certifies the caller's public key (Ed25519, ECDSA, RSA of 2048+ bits, or a FIDO security key) for every requested host and login policies allow (default: every enrolled host).
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) IssueCertificate(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshIssueCertificateInput]) (Out[apitypes.SshIssueCertificateOutput], error) {
	return Out[apitypes.SshIssueCertificateOutput]{}, notImplemented("ssh.issueCertificate")
}

// ListAuthorities is POST {basePath}/ssh/listAuthorities. Every authority key of the tenant, retired ones included: kind (user or host), status (pending, active, previous, retired), public key and fingerprint. Private keys never appear.
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) ListAuthorities(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshListAuthoritiesInput]) (Out[apitypes.SshListAuthoritiesOutput], error) {
	return Out[apitypes.SshListAuthoritiesOutput]{}, notImplemented("ssh.listAuthorities")
}

// ListCertificates is POST {basePath}/ssh/listCertificates. Issued certificates, newest first, filtered by kind, identityId, hostId or status (active, revoked, expired), paged with limit (at most 500) and offset.
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) ListCertificates(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshListCertificatesInput]) (Out[apitypes.SshListCertificatesOutput], error) {
	return Out[apitypes.SshListCertificatesOutput]{}, notImplemented("ssh.listCertificates")
}

// ListHosts is POST {basePath}/ssh/listHosts. The tenant's hosts by name, filtered by status, exact labels, or a query over names, addresses and descriptions.
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) ListHosts(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshListHostsInput]) (Out[apitypes.SshListHostsOutput], error) {
	return Out[apitypes.SshListHostsOutput]{}, notImplemented("ssh.listHosts")
}

// MyAccess is POST {basePath}/ssh/myAccess. The enrolled hosts the caller may open, with the logins and forwarding policies allow, and the settings that affect a request (MFA, security keys, lifetimes). No permission needed.
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) MyAccess(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshMyAccessInput]) (Out[apitypes.SshMyAccessOutput], error) {
	return Out[apitypes.SshMyAccessOutput]{}, notImplemented("ssh.myAccess")
}

// MyCertificates is POST {basePath}/ssh/myCertificates. The caller's own certificates in the tenant, newest first (the last 100), with their status.
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) MyCertificates(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshMyCertificatesInput]) (Out[apitypes.SshMyCertificatesOutput], error) {
	return Out[apitypes.SshMyCertificatesOutput]{}, notImplemented("ssh.myCertificates")
}

// ResetJoinToken is POST {basePath}/ssh/resetJoinToken. Returns a fresh one-time join token, for a rebuilt server or to bring a disabled host back. The host's renewal token stops working; re-enrolling revokes its previous certificates as superseded.
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) ResetJoinToken(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshResetJoinTokenInput]) (Out[apitypes.SshResetJoinTokenOutput], error) {
	return Out[apitypes.SshResetJoinTokenOutput]{}, notImplemented("ssh.resetJoinToken")
}

// RetireAuthority is POST {basePath}/ssh/retireAuthority. Stops trusting a previous (or pending) authority.
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) RetireAuthority(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshRetireAuthorityInput]) (Out[apitypes.SshRetireAuthorityOutput], error) {
	return Out[apitypes.SshRetireAuthorityOutput]{}, notImplemented("ssh.retireAuthority")
}

// RevocationList is POST {basePath}/ssh/revocationList (public: no request credential). A key revocation list, base64.
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) RevocationList(ctx context.Context, input In[apitypes.SshRevocationListInput]) (Out[apitypes.SshRevocationListOutput], error) {
	return Out[apitypes.SshRevocationListOutput]{}, notImplemented("ssh.revocationList")
}

// RevokeAllCertificates is POST {basePath}/ssh/revokeAllCertificates. Revokes every live user certificate of the tenant, after a suspected compromise.
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) RevokeAllCertificates(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshRevokeAllCertificatesInput]) (Out[apitypes.SshRevokeAllCertificatesOutput], error) {
	return Out[apitypes.SshRevokeAllCertificatesOutput]{}, notImplemented("ssh.revokeAllCertificates")
}

// RevokeCertificate is POST {basePath}/ssh/revokeCertificate. Revokes one certificate. Anyone may revoke their own user certificate; revoking someone else's needs the permission. Hosts refuse it from their next revocation list.
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) RevokeCertificate(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshRevokeCertificateInput]) (Out[apitypes.SshRevokeCertificateOutput], error) {
	return Out[apitypes.SshRevokeCertificateOutput]{}, notImplemented("ssh.revokeCertificate")
}

// RevokeIdentity is POST {basePath}/ssh/revokeIdentity. Revokes every live user certificate of one identity, for incident response.
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) RevokeIdentity(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshRevokeIdentityInput]) (Out[apitypes.SshRevokeIdentityOutput], error) {
	return Out[apitypes.SshRevokeIdentityOutput]{}, notImplemented("ssh.revokeIdentity")
}

// RotateAuthority is POST {basePath}/ssh/rotateAuthority. Starts rotating the user or host authority. A new pending key is published and trusted by hosts and clients from their next sync, and it signs from activateAuthority.
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) RotateAuthority(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshRotateAuthorityInput]) (Out[apitypes.SshRotateAuthorityOutput], error) {
	return Out[apitypes.SshRotateAuthorityOutput]{}, notImplemented("ssh.rotateAuthority")
}

// Setup is POST {basePath}/ssh/setup. Creates the tenant's user authority and host authority when they are missing, and returns every authority and the trust material to distribute. Calling it again changes nothing (created is empty).
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) Setup(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshSetupInput]) (Out[apitypes.SshSetupOutput], error) {
	return Out[apitypes.SshSetupOutput]{}, notImplemented("ssh.setup")
}

// Status is POST {basePath}/ssh/status. The tenant's SSH configuration at a glance: whether it is set up, the settings, the authorities that are not retired, hosts by status, counts of live user and host certificates and of revoked ones, a…
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) Status(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshStatusInput]) (Out[apitypes.SshStatusOutput], error) {
	return Out[apitypes.SshStatusOutput]{}, notImplemented("ssh.status")
}

// Sweep is POST {basePath}/ssh/sweep. Runs the continuous-authorization sweep for this tenant now.
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) Sweep(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshSweepInput]) (Out[apitypes.SshSweepOutput], error) {
	return Out[apitypes.SshSweepOutput]{}, notImplemented("ssh.sweep")
}

// SyncHost is POST {basePath}/ssh/syncHost (public: no request credential). A host's periodic check-in with its renewal token.
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) SyncHost(ctx context.Context, input In[apitypes.SshSyncHostInput]) (Out[apitypes.SshSyncHostOutput], error) {
	return Out[apitypes.SshSyncHostOutput]{}, notImplemented("ssh.syncHost")
}

// Trust is POST {basePath}/ssh/trust (public: no request credential). The tenant's public trust: user authority keys for hosts (trustedUserCaKeys for TrustedUserCAKeys), host authority keys, and the @cert-authority knownhosts line only when hostPatterns is set.
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) Trust(ctx context.Context, input In[apitypes.SshTrustInput]) (Out[apitypes.SshTrustOutput], error) {
	return Out[apitypes.SshTrustOutput]{}, notImplemented("ssh.trust")
}

// UpdateHost is POST {basePath}/ssh/updateHost. Changes a host's addresses, logins, labels or description (null clears it).
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) UpdateHost(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshUpdateHostInput]) (Out[apitypes.SshUpdateHostOutput], error) {
	return Out[apitypes.SshUpdateHostOutput]{}, notImplemented("ssh.updateHost")
}

// UpdateSettings is POST {basePath}/ssh/updateSettings. Changes the tenant's settings; fields left out keep their values. hostPatterns are knownhosts patterns ( and ? globs, ! negation).
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) UpdateSettings(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshUpdateSettingsInput]) (Out[apitypes.SshUpdateSettingsOutput], error) {
	return Out[apitypes.SshUpdateSettingsOutput]{}, notImplemented("ssh.updateSettings")
}

// WhoCanLogin is POST {basePath}/ssh/whoCanLogin. Access review: which active identities may log in to a host, and as which logins. Each identity is decided in a synthetic session (with MFA when assumeMfa), optionally for one login or kind.
//
// STUB: returns NOT_IMPLEMENTED until api/ssh.ts is ported.
func (api *SshAPI) WhoCanLogin(ctx context.Context, credential core.CredentialInput, input In[apitypes.SshWhoCanLoginInput]) (Out[apitypes.SshWhoCanLoginOutput], error) {
	return Out[apitypes.SshWhoCanLoginOutput]{}, notImplemented("ssh.whoCanLogin")
}

// SshRuntime is api/ssh.ts createSshRuntime().
type SshRuntime struct {
	server *ServerContext
	// Enabled Whether the `ssh` option is on.
	Enabled bool
}

// Sweep (api/ssh.ts createSshRuntime().sweep): Continuous authorization: revokes live certificates whose holder,
// session or access went away (run every few minutes).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *SshRuntime) Sweep(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/ssh.ts createSshRuntime().sweep")
	return
}

// RevocationList (api/ssh.ts createSshRuntime().revocationList): A tenant's KRL as bytes, for serving it from a
// custom route (`application/octet-stream`).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *SshRuntime) RevocationList(ctx context.Context, tenantID string, kind string) (result *core.Object, err error) {
	err = notImplemented("api/ssh.ts createSshRuntime().revocationList")
	return
}

// CreateSshRuntime builds the SshRuntime (api/ssh.ts createSshRuntime). Its methods are stubs until the module is ported.
func CreateSshRuntime(server *ServerContext) *SshRuntime {
	return &SshRuntime{server: server}
}
