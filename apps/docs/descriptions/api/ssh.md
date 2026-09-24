# ssh

The SSH certificate authority makes Better IAM the authority your servers trust. People, service accounts and agents
get short-lived OpenSSH user certificates for exactly the hosts and local accounts their policies allow. Hosts get
certificates their clients verify. Revoked certificates are refused through a key revocation list (KRL) that hosts
fetch every few minutes. The group exists when the deployment sets the `ssh` option; otherwise every method fails with
`FEATURE_DISABLED`.

## How access is decided

Each enrolled host lists the local accounts people may use. Every pair of host and login is a resource,
`ssh-login/{host}/{login}`, whose attributes are the host's labels plus `host` and `login`. Getting a certificate is
the `ssh:login` decision on those resources, so conditions, boundaries, just-in-time roles and delegation scopes all
apply. Forwarding is decided on `ssh-host/{host}` (`ssh:port-forward`, `ssh:agent-forward`, `ssh:x11-forward`). A
certificate allows a kind of forwarding only when every host it names allows it.

A certificate carries one principal per allowed pair, `{login}@{host}`. Each login's principals file on a host holds
only that host's own principal, so a certificate never opens a host or login it was not issued for.

Administration uses `iam:ssh:manage` and `iam:ssh:read` on `iam/ssh/...`. Hosts call the public methods with their join
token or renewal token. The guide is
[SSH access](https://github.com/Better-IAM/better-iam/blob/main/docs/ssh-access.md).

## setup

Creates the tenant's user authority and host authority when they are missing, and returns every authority and the
trust material to distribute. Calling it again changes nothing (`created` is empty).

- **Permission:** `iam:ssh:manage` on `iam/ssh/authorities`.
- **Audited as:** `iam:ssh:manage`.

## status

The tenant's SSH configuration at a glance: whether it is set up, the settings, the authorities that are not retired,
hosts by status, counts of live user and host certificates and of revoked ones, and hosts whose certificate ends
within 14 days.

- **Permission:** `iam:ssh:read` on `iam/ssh/settings`.

## getSettings

The tenant's settings (MFA, security keys, source-address binding, default and maximum lifetimes, host patterns), the
revocation list version, and the deployment's ceiling for `maxCertificateMs`.

- **Permission:** `iam:ssh:read` on `iam/ssh/settings`.

## updateSettings

Changes the tenant's settings; fields left out keep their values. `hostPatterns` are known_hosts patterns (`*` and `?`
globs, `!` negation). When set, every host name and address must match them, and the host authority is trusted only
for them. Empty patterns trust it for exactly the enrolled names.

- **Permission:** `iam:ssh:manage` on `iam/ssh/settings`.
- **Errors:** `INVALID_INPUT` for lifetimes outside one minute to the deployment maximum, a default above the maximum,
  or malformed patterns; `HOST_OUTSIDE_PATTERNS` when the new patterns leave an existing host uncovered.

## listAuthorities

Every authority key of the tenant, retired ones included: kind (`user` or `host`), status (`pending`, `active`,
`previous`, `retired`), public key and fingerprint. Private keys never appear.

- **Permission:** `iam:ssh:read` on `iam/ssh/authorities`.

## rotateAuthority

Starts rotating the user or host authority. A new `pending` key is published and trusted by hosts and clients from
their next sync, and it signs from `activateAuthority`. With `activate: true` the new key signs at once (after a
compromise); certificates then work only on hosts that have synced since.

- **Permission:** `iam:ssh:manage` on `iam/ssh/authorities/{kind}`.
- **Errors:** `CONFLICT` while a rotation is already pending.

## activateAuthority

Makes a pending authority the signing key. The key it replaces stays trusted as `previous`, so certificates it issued
keep working until they expire.

- **Permission:** `iam:ssh:manage` on `iam/ssh/authorities/{kind}`.
- **Errors:** `INVALID_TRANSITION` unless the authority is pending.

## retireAuthority

Stops trusting a previous (or pending) authority.

- **Permission:** `iam:ssh:manage` on `iam/ssh/authorities/{kind}`.
- **Errors:** `RESOURCE_IN_USE` while certificates it signed are still valid, unless `force: true`, which revokes them;
  `INVALID_TRANSITION` for the active authority.

## createHost

Registers a server: its `name` (unique, lowercase letters, digits, `.` and `-`, never changes), `addresses` for the host
certificate, `logins` people may be granted, and `labels` that policies read as `resource.{label}`. Returns a one-time
join token (shown once) for `enrollHost`. The name and every address must be unused by other hosts, inside the caller's
own `iam:ssh:manage` scope (decided on `iam/ssh/hosts/{address}` for each), and names the organization can vouch for:
single labels, private addresses, names under its verified domains, and within `hostPatterns` when set. Needs the
authorities from `setup`.

- **Permission:** `iam:ssh:manage` on `iam/ssh/hosts/{name}`.
- **Errors:** `CONFLICT` for a name in use; `HOST_NAME_TAKEN` for an address another host uses;
  `HOST_OUTSIDE_PATTERNS` for a name or address the organization cannot vouch for; `ACCESS_DENIED` for an address
  outside the caller's scope; `SSH_NOT_CONFIGURED`; `INVALID_INPUT` for invalid names, logins, addresses or labels.
- **Audited as:** `iam:ssh:manage`; refusals by name as a denied `iam:ssh:manage` with `metadata.reason`.

## updateHost

Changes a host's addresses, logins, labels or description (`null` clears it). New addresses reach the host
certificate, and new logins the principals files, at the host's next `syncHost` (`syncRequired` says so).

- **Permission:** `iam:ssh:manage` on `iam/ssh/hosts/{name}`.
- **Errors:** `HOST_OUTSIDE_PATTERNS`.

## getHost

One host: status, addresses, logins, labels, host key fingerprint, certificate expiry and when it last synced. Token
hashes never appear.

- **Permission:** `iam:ssh:read` on `iam/ssh/hosts/{name}`.

## listHosts

The tenant's hosts by name, filtered by `status`, exact `labels`, or a `query` over names, addresses and descriptions.

- **Permission:** `iam:ssh:read` on `iam/ssh/hosts`.

## disableHost

Takes a host out of service. Its certificate is revoked, its key is published as `@revoked` to clients and in the
revocation list, its renewal token stops working, and no user certificate names it any more.

- **Permission:** `iam:ssh:manage` on `iam/ssh/hosts/{name}`.

## resetJoinToken

Returns a fresh one-time join token, for a rebuilt server or to bring a disabled host back. The host's renewal token
stops working; re-enrolling revokes its previous certificates as `superseded`.

- **Permission:** `iam:ssh:manage` on `iam/ssh/hosts/{name}`.

## deleteHost

Deletes a host and revokes its certificate. Certificates naming it open nothing afterwards.

- **Permission:** `iam:ssh:manage` on `iam/ssh/hosts/{name}`.

## enrollHost

A server enrolls with its join token and public host key (not a security key). It gets a host certificate for its name
and addresses, the trusted user authority keys, one principals file per login, the revocation list, suggested file
paths and an sshd_config drop-in, and the renewal token (once) for `syncHost`. Public: the join token is the
credential. It works once and expires after `ssh.joinTokenMs`.

- **Audited as:** `ssh:host:enroll` (actor `ssh-host:{hostId}`).
- **Errors:** `INVALID_TOKEN` for an unknown, used or expired token or a disabled host (audited as a denied
  `ssh:host:enroll` when the host exists); `HOST_KEY_IN_USE` for another host's key; `INVALID_INPUT` for an authority
  key or a security key; `TENANT_INACTIVE`; `RATE_LIMITED`.

## syncHost

A host's periodic check-in with its renewal token. It returns the current trust, principals files and revocation list,
and a new host certificate when the host's addresses or the host authority changed or the current certificate is past
two thirds of its lifetime (`renew: true` forces one). A `publicKey` other than the enrolled one is refused, so a
stolen renewal token cannot certify an attacker's key. Public: the renewal token is the credential.

- **Audited as:** `ssh:host:renew` when a certificate is issued.
A renewed certificate comes with a new `renewalToken`; the one presented keeps working until the new one is used.
`renew: true` is honoured at most hourly. While the organization is suspended the host still syncs, without a new
certificate.

- **Errors:** `INVALID_TOKEN`; `HOST_KEY_CHANGED` (re-enroll with a new join token; audited as a denied
  `ssh:host:sync`); `RATE_LIMITED`.

## trust

The tenant's public trust: user authority keys for hosts (`trustedUserCaKeys` for `TrustedUserCAKeys`), host authority
keys, and the `@cert-authority` known_hosts line only when `hostPatterns` is set. Pending, active and previous keys are
all trusted. Public (and bound to the organization's own address): public keys and patterns only, never host names.

## clientTrust

What a member's SSH client needs: known_hosts lines trusting the host authority for the organization's enrolled names
(or its patterns), `@revoked` lines for host keys to refuse, and the host revocation list (base64 KRL) for
`RevokedHostKeys`. Needs a session of the organization.

## revocationList

A key revocation list, base64. `kind: 'user'` (the default) is for sshd `RevokedKeys`: revoked user certificates,
certificates of holders who are no longer active or whose session is gone, and every user certificate while the
organization is suspended. `kind: 'host'` is for ssh `RevokedHostKeys`: revoked host certificates and host keys no
enrolled host uses any more. The version increases with every revocation. Public, like an X.509 CRL; read outside any
transaction and cached for 10 seconds per tenant, kind and version.

## issueCertificate

Certifies the caller's public key (Ed25519, ECDSA, RSA of 2048+ bits, or a FIDO security key) for every requested host
and login policies allow (default: every enrolled host). Forwarding extensions are included only where every named host
allows them. The lifetime is the requested `ttlMs` (default from the settings), capped by the tenant maximum, the
caller's session and the account's expiry. Returns the certificate line, its principals and validity, the hosts, and
known_hosts lines. Works with user sessions, API keys, and temporary and delegated sessions, but never with an
impersonation session or a platform root override from outside the organization.

- **Permission:** a session; `ssh:login` on each `ssh-login/{host}/{login}` decides.
- **Audited as:** `ssh:certificate:issue` with the serial, key ID, hosts, fingerprint and reason; a refusal is a denied
  `ssh:login` event with `metadata.reason`.
- **Errors:** `ACCESS_DENIED`; `NOT_FOUND` for a named host that is not enrolled; `MFA_REQUIRED`;
  `SECURITY_KEY_REQUIRED`; `SOURCE_ADDRESS_UNKNOWN`; `TOO_MANY_HOSTS`; `SESSION_EXPIRING`; `IMPERSONATION_RESTRICTED`;
  `ROOT_SSH_RESTRICTED`; `SSH_NOT_CONFIGURED`.

```ts
const cert = await iam.api.ssh.issueCertificate(session, {
  tenantId,
  publicKey: 'ssh-ed25519 AAAA... alice@laptop',
  hosts: ['web-01'],
  ttlMs: 30 * 60_000,
  reason: 'hotfix 42',
});
// Save cert.certificate as ~/.ssh/id_ed25519-cert.pub
```

## myAccess

The enrolled hosts the caller may open, with the logins and forwarding policies allow, and the settings that affect a
request (MFA, security keys, lifetimes). No permission needed.

## myCertificates

The caller's own certificates in the tenant, newest first (the last 100), with their status.

## listCertificates

Issued certificates, newest first, filtered by `kind`, `identityId`, `hostId` or `status` (`active`, `revoked`,
`expired`), paged with `limit` (at most 500) and `offset`.

- **Permission:** `iam:ssh:read` on `iam/ssh/certificates`.

## getCertificate

One certificate record: kind, serial, key ID, principals, hosts and logins, extensions, key fingerprint, validity,
and revocation details.

- **Permission:** `iam:ssh:read` on `iam/ssh/certificates/{id}`.

## revokeCertificate

Revokes one certificate. Anyone may revoke their own user certificate; revoking someone else's needs the permission.
Hosts refuse it from their next revocation list.

- **Permission:** none for your own; otherwise `iam:ssh:manage` on `iam/ssh/certificates/{id}`.
- **Audited as:** `ssh:certificate:revoke` (own) or `iam:ssh:manage`.

## revokeIdentity

Revokes every live user certificate of one identity, for incident response.

- **Permission:** `iam:ssh:manage` on `iam/ssh/identities/{identityId}`.

## revokeAllCertificates

Revokes every live user certificate of the tenant, after a suspected compromise.

- **Permission:** `iam:ssh:manage` on `iam/ssh/certificates`.

## whoCanLogin

Access review: which active identities may log in to a host, and as which logins. Each identity is decided in a
synthetic session (with MFA when `assumeMfa`), optionally for one `login` or `kind`.

- **Permission:** `iam:ssh:read` on `iam/ssh/hosts/{name}`.

## sweep

Runs the continuous-authorization sweep for this tenant now. It revokes live certificates whose holder is no longer
active, whose temporary session ended, or whose hosts and logins policies no longer allow. The deployment job
`iam.ssh.sweep()` covers every tenant.

- **Permission:** `iam:ssh:manage` on `iam/ssh/certificates`.
- **Audited as:** `ssh:certificate:revoke` per revoked certificate (actor `deployment-operator`).
