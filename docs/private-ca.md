# Private certificate authority

Better IAM can run a private certificate authority (CA) for each tenant, in the style of AWS Private CA, step-ca or a
SPIFFE server. It issues X.509 certificates for mutual TLS between services, for internal HTTPS, and as workload
identities: SPIFFE X.509-SVIDs that name a service account or an agent. Certificates are authorized by the same
policies as everything else. Each name a certificate carries is decided on its own, so a team can be allowed to
certify `*.payments.internal` and nothing else. The CA signing keys are [KMS keys](key-management.md): they never
leave the server, and disabling the key stops the CA.

```ts
import { createCertificateRequest } from 'better-iam';
import { generateKeyPairSync } from 'node:crypto';

// Once: a root and an issuing (intermediate) authority.
const root = await iam.api.pki.createAuthority(admin, {
  tenantId,
  name: 'Acme Root',
  subject: { commonName: 'Acme Root CA', organization: 'Acme', country: 'US' },
  pathLength: 1,
});
const issuing = await iam.api.pki.createAuthority(admin, {
  tenantId,
  name: 'Acme Workloads',
  parentId: root.id,
  subject: { commonName: 'Acme Workload CA' },
  trustDomain: 'acme.internal',
  permitted: { dnsNames: ['internal'], uriHosts: ['acme.internal'] },
});

// A service: its own key pair, a certification request, a certificate.
const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const csr = createCertificateRequest({ privateKey, dnsNames: ['api.payments.internal'] });
const { certificatePem, chainPem, rootPem } = await iam.api.pki.issueCertificate(credential, {
  tenantId,
  authorityId: issuing.id,
  csr,
  usage: 'server',
});
```

Over HTTP the same calls are `POST {basePath}/pki/{method}`.

## Authorities

`createAuthority` makes a **root** (self-signed) or an **intermediate** (signed by a `parentId` authority of the same
tenant). Issue leaf certificates from intermediates and keep the root for signing intermediates only.

| Option                   | Meaning                                                                                                                                                                      |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `subject`                | The CA's name: `commonName` (required), `organization`, `organizationalUnit`, `locality`, `state`, `country`.                                                                |
| `keySpec`                | A new KMS signing key: `ecc-p256` (default), `ecc-p384`, `ed25519` or `rsa-2048/3072/4096`.                                                                                  |
| `keyId`                  | Or an existing KMS signing key (id or alias) the caller may `iam:kms:sign` with. The authority takes it over (see below).                                                    |
| `validityDays`           | Roots 3650 days by default, intermediates 1825; an intermediate never outlives its parent.                                                                                   |
| `pathLength`             | How many levels of CAs may sit below this one (0 to 10). An intermediate gets one less than its parent by default, and never more.                                           |
| `trustDomain`            | The SPIFFE trust domain for workload certificates (`spiffe://{trustDomain}/…`), unique across the deployment (`CONFLICT` when another tenant has it).                        |
| `permitted`              | Name constraints: `dnsNames` (suffixes such as `internal`) and `uriHosts`. They bind this authority and everything below it, and are written into intermediate certificates. |
| `crlUrl`                 | Written into issued certificates as their CRL distribution point.                                                                                                            |
| `maxValiditySeconds`     | The longest leaf certificate the authority issues (90 days by default, at most 825 days).                                                                                    |
| `defaultValiditySeconds` | Leaf validity when a request names none (one day by default).                                                                                                                |

Creating an authority needs `iam:pki:create` on `iam/pki` and a recent sign-in. An intermediate also needs
`iam:pki:update` on its parent, and must fit within the path length of every authority above it.

**Signing keys are KMS keys, managed by their authority.** A new authority gets a KMS signing key tagged
`pki-authority: {name}`; an adopted `keyId` is taken over. Either way the key is marked `managedBy: 'pki'`, and the
KMS API refuses to sign with it, grant it or use it any other way directly (`KEY_MANAGED`), so nobody can sign a
certificate body the CA did not decide. A key another authority or a data protection profile manages cannot be
adopted. The authority pins the key's current version, so rotating the KMS key never changes a CA's public key.
Disabling the KMS key stops the authority from signing anything, CRLs included, until the key is enabled again. Every
signature is audited on the key as `iam:kms:sign` with `via: 'pki'`.

`updateAuthority` disables or re-enables an authority (`state`) and changes the leaf validity limits or the CRL URL
for future certificates. A disabled authority issues nothing, and certificates it issued fail `iam.pki.verify` until
it is active again.

## Issuing certificates

`issueCertificate` takes a PEM PKCS#10 certification request (`csr`). The request's signature must verify with its
own key, which proves that the requester holds the private key. The private key never reaches IAM.
`createCertificateRequest` (exported from `better-iam` and `@better-iam/server`) builds requests without OpenSSL:

```ts
const csr = createCertificateRequest({
  privateKey, // KeyObject or PKCS#8 PEM: ECDSA P-256/P-384, Ed25519 or RSA (2048 bits or more)
  subject: { commonName: 'api.payments.internal' },
  dnsNames: ['api.payments.internal'],
  ipAddresses: ['10.0.4.12'],
});
```

- **Names.** The certificate gets the request's subject common name and subject alternative names, unless the call
  passes `commonName`, `dnsNames`, `uris`, `ipAddresses` or `emails` itself. When there are alternative names, the
  common name must be one of them (clients may fall back to it).
- **Canonical names.** What is decided is exactly what is signed: DNS names are lowercase ASCII, email addresses are
  ASCII, URIs must already be in canonical form (no user information, dot segments, uppercase hosts or default ports;
  SPIFFE IDs by the SPIFFE grammar), and IP addresses are written in canonical text, an IPv4-mapped IPv6 address as
  its IPv4 address.
- **Usage.** `usage` is `both` (the default), `server` or `client`: the extended key usage of the certificate.
- **Validity.** `validitySeconds` defaults to the authority's `defaultValiditySeconds`, is capped at its
  `maxValiditySeconds`, and never extends past the authority's own expiry. Certificates start 60 seconds in the past
  to allow for clock skew. A certificate that would expire within a minute is refused.
- **Result.** `certificatePem`, `chainPem` (the intermediates, issuer first), `rootPem`, `serialNumber`, `notBefore`,
  `notAfter` and a SHA-256 `fingerprint`. A TLS server presents `certificatePem + chainPem`, and its peers trust
  `rootPem` (or the tenant's bundle).

### Who may certify which names

Policies cannot say "every name in this list must match" directly, so the CA decides **each name separately**.
`iam:pki:issue` is evaluated on `iam/pki/{authorityId}` once for the common name and once for every subject alternative
name, and the certificate is issued only if every decision allows it. Each decision sees:

| Context key                                      | Value                                                 |
| ------------------------------------------------ | ----------------------------------------------------- |
| `resource.name`                                  | the name being decided                                |
| `resource.nameType`                              | `commonName`, `dns`, `wildcard`, `uri`, `ip`, `email` |
| `resource.usage`                                 | `server`, `client` or `both`                          |
| `resource.validitySeconds`                       | the requested validity                                |
| `resource.keyType`                               | `ecc-p256`, `ecc-p384`, `ed25519` or `rsa-{bits}`     |
| `resource.authorityId`, `resource.authorityName` | the issuing authority                                 |
| `resource.authorityType`, `resource.trustDomain` | `root` or `intermediate`, and its SPIFFE trust domain |

```json
{
  "effect": "allow",
  "actions": ["iam:pki:issue"],
  "resources": ["iam/pki/*"],
  "conditions": {
    "StringLike": { "resource.name": ["*.payments.internal", "payments.internal"] },
    "NumericLessThanEquals": { "resource.validitySeconds": 86400 }
  }
}
```

With that policy, a certificate for `api.payments.internal` is issued, while one that also names `admin.internal` is
refused as a whole.

A wildcard DNS name such as `*.payments.internal` is decided with `resource.nameType` `wildcard`, never `dns`. It covers
hosts a policy may deny one by one, so a policy that allows DNS names does not allow wildcard certificates: allow the
`wildcard` name type explicitly where you want them.

Every issued name must also fit the **name constraints** (`permitted`) of the issuing authority and every authority
above it, and so must a common name that looks like a host name. A name outside them fails with `NAME_NOT_PERMITTED`,
whoever asks, owners and root administrators included.

A `spiffe://` URI must be the certificate's only URI, and its trust domain must be the authority's `trustDomain`. Paths
under `/user/`, `/service/` and `/agent/` name identities, so only `requestCertificate` issues them: asking for one
with `issueCertificate` fails with `NAME_NOT_PERMITTED`.

## Workload identity (SPIFFE)

`requestCertificate` gives the caller a certificate for its **own** identity: an X.509-SVID whose only name is the
critical subject alternative name `spiffe://{trustDomain}/{user|service|agent}/{identityId}`, with an empty subject.
It needs `iam:pki:request` on the authority. The decision's `resource.name` is the SPIFFE ID and
`resource.identityKind` is the caller's kind. It is valid for one hour by default (`validitySeconds`, at most a day and
the authority's maximum), and never past the end of the session or API key that asked for it, or of the identity
itself. Only user sessions and API keys acting in their own right can use it: assumed roles, session tokens, delegated
agent sessions and impersonation cannot.

```ts
// A service account, with its own API key:
const svid = await iam.api.pki.requestCertificate(
  { token: serviceKey },
  { tenantId, authorityId: issuing.id, csr },
);
svid.spiffeId; // spiffe://acme.internal/service/{identityId}
```

Workloads renew their SVID before it expires by requesting a new one with a new key pair.

## Verifying certificates (mutual TLS)

A server that terminates mutual TLS verifies the client's certificate chain, and learns who is calling, with
`iam.pki.verify`:

```ts
import { X509Certificate } from 'node:crypto';

// In a Node TLS server with `requestCert: true`:
const presented = new X509Certificate(socket.getPeerCertificate().raw).toString(); // PEM
const peer = await iam.pki.verify(presented, { tenantId, usage: 'client' }); // tenantId is required
peer.identityId; // for workload certificates
peer.spiffeId;
```

`verify` accepts only certificates this deployment issued. It looks the certificate up by serial number and requires
the presented certificate to be byte-for-byte the stored one. It then walks the **stored** chain, never the chain the
client sent, checking every signature. It also checks the validity period, the requested `usage`, revocation, that the
certificate was issued in `tenantId`, that every authority in the chain is active and unexpired and within its path
length, and, for workload certificates, that the identity is still active, unexpired and (for agents) not suspended.
Anything else fails with `CERTIFICATE_INVALID` (401). CA certificates never authenticate.

## Revocation and CRLs

`revokeCertificate` (`iam:pki:revoke` on the issuing authority) takes a serial number and a `reason`:
`unspecified`, `keyCompromise`, `caCompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation` or
`privilegeWithdrawn`. A revoked certificate fails `iam.pki.verify` at once and appears on the authority's next CRL.

Revoking a subordinate authority's own certificate (it is listed under its parent, with `usage: 'ca'`) revokes the
authority itself and every authority below it (`authoritiesRevoked` in the audit event). Nothing they issued verifies
any more, and they can never issue again.

Each authority publishes a signed CRL (RFC 5280). The CRL is rebuilt when a certificate is revoked and at least
every 12 hours, and each one is valid for 24 hours. CRLs are public by design. Serve them at the `crlUrl` you gave
the authority:

```ts
// GET https://pki.acme.internal/crl/{authorityId}.crl
app.get('/crl/:id.crl', async (request) => iam.pki.crlResponse(request.params.id));
```

When a fresh CRL cannot be signed (the authority's KMS key is disabled), `crlResponse` serves the last one while it is
still valid, and answers 503 after that.

`api.pki.crl` returns the same CRL as PEM to callers with `iam:pki:read`. `iam.pki.bundle(tenantId)` (or
`api.pki.bundle`) returns the tenant's active root certificates as one PEM bundle, for relying parties to trust.
Intermediates are not trust anchors: servers send them with their own certificate (`chainPem`).

## Permissions

| Action            | Resource       | Calls                                                                                                       |
| ----------------- | -------------- | ----------------------------------------------------------------------------------------------------------- |
| `iam:pki:create`  | `iam/pki`      | `createAuthority` (plus `iam:pki:update` on the parent for intermediates)                                   |
| `iam:pki:read`    | `iam/pki/{id}` | `getAuthority`, `listAuthorities` and `listCertificates` (per authority), `getCertificate`, `crl`, `bundle` |
| `iam:pki:update`  | `iam/pki/{id}` | `updateAuthority`                                                                                           |
| `iam:pki:issue`   | `iam/pki/{id}` | `issueCertificate`, once per name                                                                           |
| `iam:pki:request` | `iam/pki/{id}` | `requestCertificate`                                                                                        |
| `iam:pki:revoke`  | `iam/pki/{id}` | `revokeCertificate`                                                                                         |

Callers from another tenant are refused before anything is looked up. Sessions that view as someone else cannot use
the CA.

## Audit

Every call is audited with its action on `pki/{authorityId}` (`pki` for tenant-wide calls). Issuing records the
serial number, every name as `{nameType}:{name}`, the usage and the expiry. Workload certificates also record the
SPIFFE ID, and revocations record the serial number and reason. Private keys never reach IAM, so they never appear
anywhere.

## Errors

| Code                    | Status | When                                                                                                |
| ----------------------- | ------ | --------------------------------------------------------------------------------------------------- |
| `INVALID_CSR`           | 400    | The request is not valid DER, is not signed by its own key, or uses an unsupported key or algorithm |
| `NAME_NOT_PERMITTED`    | 403    | A name is outside the authorities' name constraints, or a SPIFFE ID is outside the trust domain     |
| `AUTHORITY_UNAVAILABLE` | 409    | The authority (or one above it) is disabled, revoked or expired                                     |
| `CERTIFICATE_INVALID`   | 401    | `iam.pki.verify` refused a certificate                                                              |
| `KEY_STATE_INVALID`     | 409    | The authority's KMS key is disabled or pending deletion                                             |
| `KEY_MANAGED`           | 409    | Adopting a KMS key another authority or a data protection profile manages                           |
| `CONFLICT`              | 409    | The trust domain belongs to another tenant's authority                                              |
| `ACCESS_DENIED`         | 403    | A name, the authority or the workload request is not allowed                                        |
