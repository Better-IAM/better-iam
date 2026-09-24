# SSH access

Better IAM can be the certificate authority for your servers. People and machines sign in as usual and get a
short-lived OpenSSH certificate for exactly the hosts and local accounts their policies allow. Servers trust the
authority instead of per-user `authorized_keys` files. Nothing runs on the servers but stock `sshd`, a few files under
`/etc/ssh`, and a sync job.

- **User certificates** name each host and login they open. Lifetimes are hours, never longer than the session that
  asked for them.
- **Host certificates** let clients verify servers by certificate, so there are no trust-on-first-use prompts.
- **Revocation** works through a key revocation list (KRL). Servers fetch it every few minutes. A sweep revokes
  certificates whose holder or access went away.
- **Policies decide** as they do everywhere else. Getting a certificate is an `ssh:login` decision, so conditions,
  boundaries, just-in-time roles, access windows, delegation scopes and access reviews all apply.

Turn it on with the `ssh` option:

```ts
const iam = betterIam({
  // ...
  ssh: true, // or { maxUserCertificateMs, hostCertificateMs, clockSkewMs, maxHostsPerCertificate, ... }
});
```

| Option                   | Default  | Meaning                                                            |
| ------------------------ | -------- | ------------------------------------------------------------------ |
| `maxUserCertificateMs`   | 24 hours | The longest user certificate any tenant may allow (5 min – 7 days) |
| `hostCertificateMs`      | 90 days  | Host certificate lifetime (1 day – 1 year)                         |
| `clockSkewMs`            | 5 min    | How far "valid after" is backdated                                 |
| `maxHostsPerCertificate` | 64       | The most hosts one user certificate may name                       |
| `recordRetentionDays`    | 90       | How long certificate records stay after they expire                |
| `joinTokenMs`            | 24 hours | How long a host join token is valid                                |
| `issuanceLimit`          | 60       | Certificates one identity may request per rate-limit window        |

## How access is decided

Every enrolled host lists the local accounts people may use (`logins`). Every pair of host and login is a resource of
type `ssh-login`, named `ssh-login/{host}/{login}`. Its attributes are the host's labels plus `host` and `login`.
Forwarding is decided on the host itself, `ssh-host/{host}`:

| Action              | Resource                   | Grants                                              |
| ------------------- | -------------------------- | --------------------------------------------------- |
| `ssh:login`         | `ssh-login/{host}/{login}` | Logging in to the host as the login                 |
| `ssh:port-forward`  | `ssh-host/{host}`          | `permit-port-forwarding` (every named host must allow it) |
| `ssh:agent-forward` | `ssh-host/{host}`          | `permit-agent-forwarding`                           |
| `ssh:x11-forward`   | `ssh-host/{host}`          | `permit-X11-forwarding`                             |

```json
{
  "version": 1,
  "statements": [
    {
      "effect": "allow",
      "actions": ["ssh:login"],
      "resources": ["ssh-login/*/deploy"],
      "conditions": { "StringEquals": { "resource.environment": "staging" } }
    },
    {
      "effect": "allow",
      "actions": ["ssh:login"],
      "resources": ["ssh-login/db-*/postgres"],
      "conditions": { "Bool": { "principal.mfa": true } }
    },
    { "effect": "allow", "actions": ["ssh:port-forward"], "resources": ["ssh-host/*"] }
  ]
}
```

A certificate carries one principal per allowed pair, `{login}@{host}`. The principals file of each login on a host
holds only that host's own principal, so a certificate opens nothing it was not issued for. A host that was not set up
with a principals file refuses these certificates outright, because a principal such as `deploy@web-01` never equals a
local user name.

The same decisions work through the generic API: `iam.authorize({ action: 'ssh:login', resource: { type: 'ssh-login',
id: 'web-01/deploy' } })`, `policies.whoCan`, `policies.simulate`, and `ssh.whoCanLogin` for a host.

Two principals never get certificates:

- **"View as" sessions.** An impersonation session is refused (`IMPERSONATION_RESTRICTED`).
- **The platform root override in another organization.** A root administrator needs a role in the organization like
  anyone else (`ROOT_SSH_RESTRICTED`). The root tenant's own hosts are the exception.

## Setting up

An administrator with `iam:ssh:manage` creates the tenant's two authorities, one for users and one for hosts, and then
registers hosts. Hosts can be registered only once the authorities exist (`SSH_NOT_CONFIGURED` otherwise).

```ts
await iam.api.ssh.setup(admin, { tenantId });

const { host, joinToken } = await iam.api.ssh.createHost(admin, {
  tenantId,
  name: 'web-01',
  addresses: ['web-01.corp.example.com', '10.0.0.5'],
  logins: ['deploy', 'ubuntu'],
  labels: { environment: 'staging', team: 'payments' },
});
```

Host names use lowercase letters, digits, `.` and `-`. The name never changes, because it is part of every principal.
Labels (up to 32) are what policies read as `resource.{label}`.

The host certificate names the host's name and every address, so the authority must never vouch for a name the
organization does not own:

- **Owned names.** Without `hostPatterns`, a name or address must be a single label (`web-01`), a private address
  (`10.0.0.5`, `fd00::5`), or a name under one of the organization's [verified domains](enterprise.md). With
  `hostPatterns`, it must also match them; a public IP address needs a pattern that fixes its prefix (`203.0.113.*`).
  Anything else is refused with `HOST_OUTSIDE_PATTERNS`.
- **Unique names.** No two hosts of the organization share a name or address (`HOST_NAME_TAKEN`).
- **Names within your scope.** `iam:ssh:manage` is decided on `iam/ssh/hosts/{name}` for the host's name and for every
  address, so an administrator allowed `iam/ssh/hosts/team-a-*` cannot give a host the address `payroll.acme.com`.

Removing an address revokes the host's certificate at once; the host gets a new one at its next sync. Refusals are
audited as denied `iam:ssh:manage` events.

### Enrolling a server

On the server, run the CLI with the join token. It is valid for 24 hours and works once.

```bash
BETTER_IAM_SSH_JOIN_TOKEN=biam_sshj.... better-iam ssh-host-enroll --url https://iam.example.com
```

`enrollHost` returns everything sshd needs, and the CLI writes it:

| File                                       | For                                              |
| ------------------------------------------ | ------------------------------------------------ |
| `/etc/ssh/ssh_host_ed25519_key-cert.pub`   | `HostCertificate`, signed by the host authority  |
| `/etc/ssh/better-iam/user-ca.pub`          | `TrustedUserCAKeys`                              |
| `/etc/ssh/better-iam/principals/{login}`   | `AuthorizedPrincipalsFile` (`{login}@{host}`)    |
| `/etc/ssh/better-iam/revoked.krl`          | `RevokedKeys`                                    |
| `/etc/ssh/sshd_config.d/00-better-iam.conf` | The drop-in naming the four above                |
| `/etc/ssh/better-iam/renewal-token`        | The host's credential for syncing (mode 0600)    |

sshd uses the first value it reads, so the drop-in's name sorts first; check the result with `sshd -T`. Then reload
sshd, and run `better-iam ssh-host-sync` every few minutes from cron or a systemd timer. Each sync fetches the current
trust, principals and revocation list, and issues a new host certificate when the current one is two thirds through its
life, the host's addresses changed, or the host authority rotated (`renew: true` forces one, at most hourly). A new
certificate comes with a new renewal token, which the CLI saves; the previous token keeps working until the new one is
used, so a lost response never locks a host out. The CLI also deletes principals files of logins the host no longer
has. Enrollment and syncs are rate limited per host.

Without the CLI, call the public routes yourself. Every POST needs `Content-Type: application/json` and
`X-Better-IAM: 1`.

```bash
curl -s https://iam.example.com/api/iam/ssh/syncHost \
  -H 'content-type: application/json' -H 'x-better-iam: 1' \
  -d "{\"renewalToken\":\"$(cat /etc/ssh/better-iam/renewal-token)\"}"
```

The renewal token never moves a host to another key. A sync with a different host key fails with `HOST_KEY_CHANGED`
(audited as a denied `ssh:host:sync`), so a stolen token cannot produce a host certificate for an attacker's key. After
rebuilding a server, re-enroll it with a new join token from `ssh.resetJoinToken`. Every certificate a host held before
is revoked as `superseded` whenever it gets a new one, and a key no enrolled host uses any more is published to
clients as revoked. A host key must not be one of the organization's authority keys or another host's key
(`HOST_KEY_IN_USE`), so revoking a host can never revoke anything else.

While the organization is suspended, hosts keep syncing but get no new certificates, and their revocation list
revokes every user certificate.

## Getting a certificate

People (and service accounts or agents, with their API keys) call `issueCertificate`, or run the CLI:

```bash
better-iam login --url https://iam.example.com
better-iam ssh-cert --tenant ten_123                 # every host and login you may use
better-iam ssh-cert --hosts web-01 --logins deploy --ttl-minutes 30 --reason "hotfix 42"
ssh deploy@web-01.corp.example.com
```

`ssh-cert` saves the certificate next to your key (`~/.ssh/id_ed25519-cert.pub`), where ssh finds it. It also writes
the host authority, for the organization's host names, to `~/.ssh/better-iam_known_hosts`, and the host revocation list
to `~/.ssh/better-iam_revoked_hosts`. Add both once:

```
# ~/.ssh/config
Host *.corp.example.com web-* db-*
  UserKnownHostsFile ~/.ssh/known_hosts ~/.ssh/better-iam_known_hosts
  RevokedHostKeys ~/.ssh/better-iam_revoked_hosts
```

`clientTrust` returns the same two for members. The public `trust` route gives only the authority keys (and the
`@cert-authority` line for configured `hostPatterns`), so the host inventory is never public.

```ts
const cert = await iam.api.ssh.issueCertificate(session, {
  tenantId,
  publicKey: 'ssh-ed25519 AAAA... alice@laptop',
  hosts: ['web-01'], // optional; default: every enrolled host you may open
  logins: ['deploy'], // optional
  ttlMs: 30 * 60_000, // optional; default and maximum from the tenant settings
  reason: 'hotfix 42', // optional; audited
});
// cert.certificate: 'ssh-ed25519-cert-v01@openssh.com AAAA...'
// cert.principals: ['deploy@web-01'], cert.validBefore, cert.hosts, cert.knownHosts
```

`myAccess` lists the hosts, logins and forwarding a person may use (like `tsh ls`), and `myCertificates` lists their
certificates. Anyone may revoke their own certificate with `revokeCertificate`.

A certificate's lifetime is the requested one, capped by:

- the tenant's maximum and the account's expiry;
- the session that asked for it. A certificate lives only as long as that session: signing out, revoking the person's
  sessions, revoking the API key, or its idle timeout ends it at the next revocation list;
- the end of any time-limited grant that allows `ssh:login`: a just-in-time activation, a temporary binding or group
  membership, or an access window (a standing grant sets no limit);
- ten minutes for agents acting for people (delegated sessions).

Issuing is rate limited per identity (`ssh.issuanceLimit`, 60 per window). The key ID sshd logs is
`{email} ({identityId})`, plus `via agent {id}` for delegated sessions. Supported keys are Ed25519, ECDSA
(P-256/384/521), RSA of 2048 bits or more, and FIDO security keys (`ed25519-sk`, `ecdsa-sk`).

Issuing is audited as `ssh:certificate:issue`, with the serial, hosts, fingerprint and reason. A refusal is a denied
`ssh:login` event whose `metadata.reason` names the rule that refused it.

## Tenant settings

`updateSettings` (`iam:ssh:manage`):

| Setting                   | Default  | Effect                                                                                   |
| ------------------------- | -------- | ---------------------------------------------------------------------------------------- |
| `requireMfa`              | `false`  | People need an MFA session (`MFA_REQUIRED`); service accounts and agents are unaffected  |
| `requireSecurityKey`      | `false`  | Only FIDO security keys are certified (`SECURITY_KEY_REQUIRED`)                           |
| `requireUserVerification` | `false`  | Security-key certificates carry `verify-required`: PIN or biometric at every login        |
| `bindSourceAddress`       | `false`  | Certificates carry `source-address` with the caller's IP (needs `http.clientInfo` to know it) |
| `defaultCertificateMs`    | 8 hours  | Lifetime when a request names none                                                        |
| `maxCertificateMs`        | 16 hours | The longest a request may ask for                                                         |
| `hostPatterns`            | none     | known_hosts patterns the host authority is trusted for                                    |

Without `hostPatterns`, members' clients trust the host authority for exactly the enrolled hosts' names and addresses,
never for `*`. With patterns such as `['*.corp.example.com', 'web-*', '10.20.*', '!bastion.corp.example.com']`, every
host name and address must match them as well. Each positive pattern must end in a verified domain of the organization,
fix an address prefix, or be a short name; `*` alone is refused, and the patterns must cover every host already
enrolled. The authority can then never vouch for a name like `github.com`, even if an administrator enters it.

## Revocation

There are two key revocation lists (KRLs), both from `revocationList`:

- **`user`** (the default), which hosts load as `RevokedKeys` and refuse from their next sync. It holds:
  - certificates revoked by hand: `revokeCertificate`, `revokeIdentity` (everything one person holds), and
    `revokeAllCertificates` (the whole tenant, for a suspected compromise);
  - certificates of people and machines who are no longer active, or whose session is gone, even before the sweep
    marks them;
  - every user certificate while the organization is suspended.
- **`host`** (`kind: 'host'`), which clients load as `RevokedHostKeys`. It holds revoked host certificates (disabled,
  deleted, re-enrolled hosts, removed addresses) and host keys no enrolled host uses any more. Members also get these
  keys as `@revoked` lines in known_hosts.

The sweep job, `iam.ssh.sweep()` or `better-iam ssh-sweep`, re-checks every live user certificate every few minutes
against the very session that requested it, with the same checks every request gets. It revokes certificates whose
holder is no longer active (`identity-inactive`), whose session was revoked, expired or no longer validates
(`session-ended`), or whose hosts, logins or forwarding policies no longer allow (`access-changed`, which also covers a
login removed from a host). Removing a binding therefore takes SSH access away within minutes, not when the certificate
expires. `revocationList` is public (like an X.509 CRL, it holds serials and public keys only). It is read outside any
transaction and cached for 10 seconds per tenant, kind and revocation version. `iam.ssh.revocationList(tenantId, kind)`
returns the same list as bytes for a custom route.

## Rotating authorities

Rotation is two-phase, so no certificate stops working unexpectedly:

1. `rotateAuthority({ kind: 'user' })` publishes a new `pending` key. Hosts trust it from their next sync.
2. `activateAuthority({ authorityId })` makes it sign. The old key stays trusted as `previous`.
3. `retireAuthority({ authorityId })` stops trusting the previous key once its certificates have expired. It is refused
   with `RESOURCE_IN_USE` while valid certificates remain, unless you pass `force: true`, which revokes them.

After a compromise, `rotateAuthority({ kind, activate: true })` switches at once. Certificates then work only on hosts
that have synced since. Host authority rotations re-issue host certificates at each host's next sync.

Authority private keys are Ed25519, sealed with the deployment secret, and re-sealed by `iam.rotateSecrets()`. No
API response ever contains them.

## API

| Method                                                       | Access           |
| ------------------------------------------------------------ | ---------------- |
| `setup`, `updateSettings`, `rotateAuthority`, `activateAuthority`, `retireAuthority` | `iam:ssh:manage` |
| `createHost`, `updateHost`, `disableHost`, `resetJoinToken`, `deleteHost`            | `iam:ssh:manage` |
| `revokeCertificate` (someone else's), `revokeIdentity`, `revokeAllCertificates`, `sweep` | `iam:ssh:manage` |
| `status`, `getSettings`, `listAuthorities`, `getHost`, `listHosts`, `listCertificates`, `getCertificate`, `whoCanLogin` | `iam:ssh:read` |
| `issueCertificate`, `myAccess`, `myCertificates`, `clientTrust`, `revokeCertificate` (own) | a session; `ssh:login` decides |
| `enrollHost` (join token), `syncHost` (renewal token), `trust`, `revocationList`     | public           |

Errors: `FEATURE_DISABLED`, `SSH_NOT_CONFIGURED`, `MFA_REQUIRED`, `SECURITY_KEY_REQUIRED`, `SOURCE_ADDRESS_UNKNOWN`,
`TOO_MANY_HOSTS`, `SESSION_EXPIRING`, `ROOT_SSH_RESTRICTED`, `HOST_OUTSIDE_PATTERNS`, `HOST_NAME_TAKEN`,
`HOST_KEY_IN_USE`, `HOST_KEY_CHANGED`, `INVALID_TOKEN`, `RATE_LIMITED`.

Audit events: `ssh:certificate:issue`, `ssh:certificate:revoke` (sweep and self-service), `ssh:host:enroll`,
`ssh:host:renew`, denied `ssh:host:enroll` / `ssh:host:sync` (a real host's token refused, a key swap), denied
`ssh:login`, and the `iam:ssh:*` administration operations (denied ones name the refusal in `metadata.reason`).
