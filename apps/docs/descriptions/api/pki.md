# pki

A private certificate authority per tenant, in the style of AWS Private CA, step-ca or a SPIFFE server. It issues
X.509 certificates for mutual TLS, internal HTTPS and workload identity (SPIFFE X.509-SVIDs). Authorities sign with KMS
keys pinned to one version. Every name a certificate carries is decided by policy on its own. `iam.pki` serves CRLs,
trust bundles and certificate verification to servers. The repository guide is `docs/private-ca.md`.

## Deciding names

Policies cannot require that every entry of a list matches, so issuing evaluates `iam:pki:issue` on
`iam/pki/{authorityId}` once for the common name and once for each subject alternative name. The certificate is issued
only if every decision allows it. Each decision sees `resource.name`, `resource.nameType` (`commonName`, `dns`,
`wildcard`, `uri`, `ip` or `email`), `resource.usage`, `resource.validitySeconds`, `resource.keyType` and the
authority's `resource.authorityId`, `resource.authorityName`, `resource.authorityType` and `resource.trustDomain`.
Names are decided in the canonical form that is signed. A wildcard DNS name is its own name type, so allowing DNS names
does not allow wildcard certificates. Names must also fit the name constraints (`permitted`) of the issuing authority
and every authority above it, whoever asks.

## createAuthority

Creates a root (self-signed) or an intermediate authority (signed by `parentId` in the same tenant), with a new KMS
signing key (`keySpec`, default `ecc-p256`) or an existing one (`keyId`) whose current version is pinned. Either way
the key becomes managed by the authority (`managedBy: 'pki'`), and the keys API refuses to use it directly.

- **Permission:** `iam:pki:create` on `iam/pki` with recent authentication; `iam:pki:update` on the parent for an
  intermediate; `iam:kms:sign` on an existing key.
- **Audited as:** `iam:pki:create` (metadata: `authorityId`, `name`, `type`, `keyId`, `serialNumber`, `parentId`).
- **Errors:** `INVALID_INPUT` for a missing `subject.commonName`, an invalid key spec, or a path length the chain
  does not allow; `CONFLICT` for a name in use or a trust domain another tenant has; `KEY_MANAGED` for a key another
  authority or profile manages; `AUTHORITY_UNAVAILABLE` when the parent chain is not active;
  `LIMIT_EXCEEDED` past 50 authorities; `RECENT_AUTH_REQUIRED`.

```ts
const issuing = await iam.api.pki.createAuthority(admin, {
  tenantId,
  name: 'Acme Workloads',
  parentId: root.id,
  subject: { commonName: 'Acme Workload CA' },
  trustDomain: 'acme.internal',
  permitted: { dnsNames: ['internal'], uriHosts: ['acme.internal'] },
});
```

## listAuthorities

The tenant's authorities the caller may read, oldest first.

- **Permission:** `iam:pki:read`, evaluated for each authority.

## getAuthority

One authority: subject, type, parent, KMS key and pinned version, certificate, validity, state, trust domain, name
constraints and leaf limits.

- **Permission:** `iam:pki:read`.

## updateAuthority

Disables or re-enables an authority (`state`), and changes `maxValiditySeconds`, `defaultValiditySeconds` or
`crlUrl` (`null` clears it) for future certificates. A disabled authority issues nothing, and what it issued fails
verification until it is active again.

- **Permission:** `iam:pki:update`.
- **Errors:** `AUTHORITY_UNAVAILABLE` for a revoked authority.

## issueCertificate

Issues a certificate for the key in a PEM PKCS#10 request (`csr`). The request must be signed by its own key, which
proves the requester holds the private key. Names come from the request unless `commonName`, `dnsNames`, `uris`,
`ipAddresses` or `emails` are given. `usage` is `both` (default), `server` or `client`. Validity defaults to the
authority's `defaultValiditySeconds`, is capped at its `maxValiditySeconds`, and never outlasts the authority.
Returns `certificatePem`, `chainPem`, `rootPem`, `serialNumber`, `notBefore`, `notAfter` and `fingerprint`.

- **Permission:** `iam:pki:issue` for every name on the certificate.
- **Audited as:** `iam:pki:issue` (metadata: `serialNumber`, `names`, `notAfter`, `usage`).
- **Errors:** `INVALID_CSR` for a malformed or unsigned request or an unsupported key; `NAME_NOT_PERMITTED` for a name
  outside the name constraints or a SPIFFE ID outside the trust domain; `INVALID_INPUT` for a certificate with no
  names, two URIs beside a SPIFFE ID, or a validity beyond the maximum; `AUTHORITY_UNAVAILABLE`;
  `KEY_STATE_INVALID` when the authority's KMS key is disabled.

## requestCertificate

A workload certificate (SPIFFE X.509-SVID) for the caller's own identity. Its only name is
`spiffe://{trustDomain}/{user|service|agent}/{identityId}`, it has an empty subject, and it is valid for one hour by
default. For user sessions and API keys acting in their own right.

- **Permission:** `iam:pki:request` on the authority; `resource.name` is the SPIFFE ID and `resource.identityKind` the
  caller's kind.
- **Audited as:** `iam:pki:request` (metadata: `serialNumber`, `spiffeId`, `notAfter`).
- **Errors:** `INVALID_INPUT` when the authority has no trust domain; `ACCESS_DENIED` for assumed roles, session
  tokens, delegated sessions and impersonation.

## listCertificates

Certificates the caller may read, newest first, filtered by `authorityId`, `status` (`valid`, `revoked`,
`expired`) or `identityId`.

- **Permission:** `iam:pki:read` on each certificate's authority.

## getCertificate

One certificate by serial number (hexadecimal, colons allowed).

- **Permission:** `iam:pki:read` on its authority.

## revokeCertificate

Revokes a certificate with a `reason` (`unspecified`, `keyCompromise`, `caCompromise`, `affiliationChanged`,
`superseded`, `cessationOfOperation` or `privilegeWithdrawn`). It fails verification at once and appears on the next
CRL. Revoking a subordinate authority's certificate revokes that authority too.

- **Permission:** `iam:pki:revoke` on the issuing authority.
- **Audited as:** `iam:pki:revoke` (metadata: `serialNumber`, `reason`, `subordinateId`).
- **Errors:** `CONFLICT` when already revoked.

## crl

The authority's current certificate revocation list as PEM, rebuilt after revocations and at least every 12 hours.

- **Permission:** `iam:pki:read`. Relying parties fetch the same CRL without a credential through
  `iam.pki.crlResponse`.

## bundle

The tenant's active root certificates as one PEM bundle: what relying parties trust. Intermediates travel in each server's chain.

- **Permission:** `iam:pki:read` (per authority).
