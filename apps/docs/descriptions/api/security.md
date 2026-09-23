# security

Network blocks shut out an IP address or range during an incident, for one tenant or, set by root administrators,
for the whole installation. When a credential-stuffing attack or a compromised network shows up in the sign-in
failures, you need to stop it now, without touching each account. A block is the incident-response counterpart of
a tenant's `allowedIpRanges` allowlist. See
[network blocks](/docs/operations/security#network-blocks-and-ip-bound-sessions).

## How network blocks work

A live block refuses every sign-in and authentication flow, every existing session whose recorded client IP falls
in the blocked network, and every API key or assumed-role token presented from it, with `IP_BLOCKED`. Blocks are
checked before rate limits and credentials, so traffic from a blocked address cannot count against anyone's
rate limits.

- **Scope.** An organization's blocks apply to that tenant. Root administrators can set a `platform` block on the
  root tenant, which applies to every tenant.
- **Networks.** A single IPv4 or IPv6 address, or a CIDR block such as `198.51.100.0/24`.
- **Lifetime.** With `durationMs` (one minute to one year) a block lapses by itself; without it, it stays until
  [`unblockNetwork`](#unblocknetwork) lifts it. Lapsed blocks are deleted later by the retention worker
  (`purgeDeleted`).
- **Addresses.** Blocks only work when the deployment records client IPs (`http.clientInfo`); a request without a
  known IP is never blocked.
- **Propagation.** A change applies at once in the server process that made it; other processes pick it up within
  seconds.

Every change is audited twice: once as the `iam:security:manage` operation and once as `security:network-block` or
`security:network-unblock`, with the network and scope in the metadata. Subscribe a webhook to `security:*` to
alert on them.

## blockNetwork

Blocks an IP address or CIDR range for the tenant, or for the whole platform, optionally for a limited time.

- **Permission:** `iam:security:manage` on `iam/security/networks`, with recent authentication. A `platform` block
  also requires a root administrator acting on the root tenant.
- **Audited as:** `iam:security:manage` and `security:network-block` (metadata: `network`, `reason`, `platform`,
  `expiresAt`, and `renewed`).
- **Errors:** `INVALID_INPUT` when `network` is not an IPv4 or IPv6 address or CIDR block, `reason` is empty, the
  duration is out of range, or the network includes your own address; `ACCESS_DENIED` for a platform block from
  anyone but a root administrator on the root tenant; `RECENT_AUTH_REQUIRED` without recent authentication;
  `IMPERSONATION_RESTRICTED` from a "view as" session.

A block that would cover your own address, either the one your session was issued from or the one this request
comes from, is refused, so you cannot lock yourself out of the session you need to lift it. Blocking a network that
is already blocked in the same scope renews that block: the reason, the expiry, and who set it are replaced, and
the audit metadata says `renewed: true`.

```ts
await iam.api.security.blockNetwork(credential, {
  tenantId,
  network: '203.0.113.0/24',
  reason: 'Credential stuffing, incident 4211',
  durationMs: 24 * 60 * 60 * 1000,
});
```

## listBlocks

Lists the tenant's network blocks, newest first, each with `active` telling whether it still applies.

- **Permission:** `iam:security:read` on `iam/security/networks`.
- **Audited as:** `iam:security:read`.

Lapsed blocks stay in the list with `active: false` until the retention worker deletes them. Platform blocks are
listed on the root tenant, where they were set.

## unblockNetwork

Lifts a network block before it lapses.

- **Permission:** `iam:security:manage` on `iam/security/networks`, with recent authentication. Lifting a platform
  block also requires a root administrator acting on the root tenant.
- **Audited as:** `iam:security:manage` and `security:network-unblock` (metadata: `network`, `platform`).
- **Errors:** `NOT_FOUND` when the block is not in this tenant; `ACCESS_DENIED` for a platform block from anyone but
  a root administrator; `RECENT_AUTH_REQUIRED` without recent authentication.

The block is deleted, so traffic from the network is accepted again right away (within seconds on other server
processes).
