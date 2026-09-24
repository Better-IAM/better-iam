# Key management

Better IAM includes a key management service in the style of AWS KMS. Each tenant keeps its own cryptographic keys.
Applications use them through the `keys` API group to encrypt, decrypt, sign, verify and compute MACs, and the key
material never leaves the server. The permissions, conditions and audit trail are the ones the rest of the platform
uses. Keys are tenant resources, so a policy can let a payments service decrypt only with keys tagged
`team: payments`, and only for records whose encryption context says `app: billing`.

```ts
const key = await iam.api.keys.create(credential, {
  tenantId,
  alias: 'alias/customer-records',
  tags: { team: 'payments' },
  rotationPeriodDays: 365,
});

const { ciphertext } = await iam.api.keys.encrypt(credential, {
  tenantId,
  keyId: 'alias/customer-records',
  plaintext: 'card on file: 4242',
  encryptionContext: { customer: 'cus_123' },
});

const { plaintext } = await iam.api.keys.decrypt(credential, {
  tenantId,
  ciphertext,
  encryptionContext: { customer: 'cus_123' },
});
```

Over HTTP the same calls are `POST {basePath}/keys/{method}`.

## Key kinds

| `keySpec`                           | `keyUsage`          | What it does                                                                   |
| ----------------------------------- | ------------------- | ------------------------------------------------------------------------------ |
| `aes-256-gcm` (default)             | `encrypt`           | `encrypt` / `decrypt` up to 4 KiB, `generateDataKey`, `reEncrypt`              |
| `hmac-sha256`, `-sha384`, `-sha512` | `mac`               | `generateMac` / `verifyMac`, HS256/384/512 tokens with `signJwt`               |
| `ecc-p256`, `ecc-p384`              | `sign`              | ES256 / ES384 signatures and tokens                                            |
| `ed25519`                           | `sign`              | EdDSA signatures and tokens                                                    |
| `rsa-2048`, `rsa-3072`, `rsa-4096`  | `sign` or `encrypt` | PS256-PS512 and RS256-RS512 signatures, or RSA-OAEP (SHA-256) for small values |

An RSA key needs an explicit `keyUsage`. Every other spec has exactly one usage.

A tenant keeps at most 1000 keys. A key keeps at most 1000 versions, 50 aliases and 50 grants.

## Keys, versions and aliases

A key has an id (a UUID) and any number of **aliases** of the form `alias/{name}`. An alias names one key per tenant.
Every call that takes a `keyId` accepts an alias too. `updateAlias` points an alias at another key of the same kind
and usage, so applications that name the alias switch keys without a deploy. Moving an alias needs
`iam:kms:update` on both keys.

Each key has **versions**. Encrypting, signing and computing MACs use the current version. Decrypting and verifying
use whichever version produced the ciphertext, signature or token, so rotation never breaks existing data:

- `rotate` creates a new version on demand.
- `rotationPeriodDays` (1 to 3650) rotates automatically. The scheduler job `iam.kms.maintain()` performs it and
  records `kms:key-rotate` (actor `deployment-operator`). Setting `null` in `update` stops automatic rotation.

`listVersions` shows each version's origin (`create`, `rotate` or `automatic`) and, for asymmetric keys, a
fingerprint of its public key.

## Encryption

`encrypt` takes `plaintext` (UTF-8 text) or `plaintextBase64` (bytes) and returns a self-describing ciphertext:

```
kms1.{keyId}.{version}.{t|b}.{payload}
```

The ciphertext carries the key and version, so `decrypt` needs only the ciphertext. Pass `keyId` to `decrypt` as well
if you want to insist on a particular key. The `t`/`b` marker records whether the plaintext was text or bytes, and
`decrypt` returns it in the same form (`plaintext` or `plaintextBase64`). The marker is authenticated with the rest
of the header.

### Encryption context

An **encryption context** is up to 16 non-secret key/value pairs that are bound to the ciphertext as additional
authenticated data. `decrypt` must present exactly the same pairs, otherwise it fails with `INVALID_CIPHERTEXT`. A
tampered ciphertext fails the same way. Contexts do three jobs:

- **Integrity.** A ciphertext copied to another record cannot be decrypted as that record.
- **Authorization.** Policies read the pairs as `resource.encryptionContext.{key}` and their names as
  `resource.encryptionContextKeys`.
- **Audit.** Each call's audit event records the context.

Contexts are written to the audit trail, so they must never contain secrets.

### Data keys (envelope encryption)

Direct encryption is limited to 4 KiB. For larger data, use envelope encryption:

1. `generateDataKey` returns a fresh random key (`plaintextBase64`, 16 to 64 bytes) and the same key encrypted under
   the KMS key (`ciphertext`).
2. Encrypt the data locally with the plaintext key, store the `ciphertext` next to it, and discard the plaintext.
3. To read the data, `decrypt` the stored ciphertext to get the data key back.

`includePlaintext: false` returns only the encrypted data key, for a service that stores it for another service to
open later. `reEncrypt` moves a ciphertext to another key or context without the plaintext leaving the server. It
needs `iam:kms:decrypt` on the source key and `iam:kms:encrypt` on the destination key, and it is audited as both.

RSA keys with `keyUsage: 'encrypt'` use RSA-OAEP with SHA-256, with the header and context as the OAEP label. They
accept only small values: 190 bytes with a 2048-bit key. Use data keys for anything larger. Because of the label, a
value encrypted offline with the public key is not a KMS ciphertext; encrypt through `encrypt`.

## Signatures, MACs and tokens

- `sign` / `verify` work on a `message` (text) or `messageBase64` of up to 64 KiB. ECDSA signatures are DER-encoded
  by default. `format: 'jose'` returns the raw `r||s` form that JWS uses. `verify` returns `{ valid }`, and a
  mismatch is not an error.
- `generateMac` / `verifyMac` compute and check HMACs. The check is constant-time.
- `publicKey` returns an asymmetric version's key as SPKI PEM and JWK. `jwks` returns every version as a JWK Set.
  Anyone holding the public key can verify signatures without calling IAM.
- `signJwt` signs a JWT with a signing key or a MAC key. The header is `{ alg, kid, typ }`, with `kid` =
  `{keyId}.{version}` (the same `kid` the JWKS uses), `iat` is added when absent, and `exp` comes from
  `expiresInSeconds`. Policies see what the token names: `resource.jwt` (true), `resource.jwt.typ`,
  `resource.jwt.sub`, `resource.jwt.iss`, and `resource.jwt.aud` (or `resource.jwt.audiences` for a list). A policy
  can therefore let a service mint tokens for one issuer only, or mint tokens but never sign raw bytes.
- `verifyJwt` finds the version from the `kid` and accepts only the key's own algorithms, so `alg: none` and
  algorithm swaps are refused. Tokens with a `crit` header, or with an `exp` or `nbf` that is not a number, are
  refused as well. It checks `exp` and `nbf` with a clock tolerance (60 s by default), and `aud` and `iss` when you pass
  them.

Base64 inputs (signatures, MACs, ciphertexts, `plaintextBase64`) must be canonical: one byte string has exactly one
accepted spelling, so a cache keyed by the string cannot be sidestepped.

## Permissions

KMS calls are authorized like every other IAM operation: a policy names the action and the resource.

| Action                                        | Resource               | Calls                                                                                |
| --------------------------------------------- | ---------------------- | ------------------------------------------------------------------------------------ |
| `iam:kms:create`                              | `iam/kms`              | `create`                                                                             |
| `iam:kms:read`                                | `iam/kms/{id}`         | `get`, `list` (per key), `listVersions`, `listGrants`, `publicKey`, `jwks`           |
| `iam:kms:read`                                | `iam/kms`              | `listAliases` without `keyId`                                                        |
| `iam:kms:update`                              | `iam/kms/{id}`         | `update`, `enable`, `disable`, `rotate`, `createAlias`, `updateAlias`, `deleteAlias` |
| `iam:kms:update`                              | `iam/kms/alias/{name}` | `create` with an `alias`, `createAlias`, `updateAlias`, `deleteAlias`                |
| `iam:kms:delete`                              | `iam/kms/{id}`         | `scheduleDeletion` (also needs recent authentication), `cancelDeletion`              |
| `iam:kms:grant`                               | `iam/kms/{id}`         | `createGrant`, `revokeGrant`                                                         |
| `iam:kms:encrypt`                             | `iam/kms/{id}`         | `encrypt`, and the destination of `reEncrypt`                                        |
| `iam:kms:decrypt`                             | `iam/kms/{id}`         | `decrypt`, and the source of `reEncrypt`                                             |
| `iam:kms:generate-data-key`                   | `iam/kms/{id}`         | `generateDataKey`                                                                    |
| `iam:kms:sign` / `iam:kms:verify`             | `iam/kms/{id}`         | `sign`, `verify`, and `signJwt` / `verifyJwt` with signing keys                      |
| `iam:kms:generate-mac` / `iam:kms:verify-mac` | `iam/kms/{id}`         | `generateMac`, `verifyMac`, and `signJwt` / `verifyJwt` with MAC keys                |

Conditions can use these attributes of the key:

| Context key                             | Value                                       |
| --------------------------------------- | ------------------------------------------- |
| `resource.keyId`                        | the key id                                  |
| `resource.keySpec`, `resource.keyUsage` | for example `aes-256-gcm`, `encrypt`        |
| `resource.keyState`                     | `enabled`, `disabled` or `pending-deletion` |
| `resource.aliases`                      | the key's aliases (use `ArrayContains`)     |
| `resource.tags.{key}`                   | each tag                                    |
| `resource.createdBy`                    | the identity that created the key           |
| `resource.encryptionContext.{key}`      | encrypt, decrypt and data key calls         |
| `resource.encryptionContextKeys`        | the context's key names, sorted             |
| `resource.algorithm`                    | signing, MAC and token calls                |

```json
{
  "version": 1,
  "statements": [
    {
      "effect": "allow",
      "actions": ["iam:kms:encrypt", "iam:kms:decrypt", "iam:kms:generate-data-key"],
      "resources": ["iam/kms/*"],
      "conditions": {
        "StringEquals": {
          "resource.tags.team": "payments",
          "resource.encryptionContext.app": "billing"
        }
      }
    }
  ]
}
```

For `create`, the attributes describe the key being requested: `resource.keySpec`, `resource.keyUsage` and the
requested `resource.tags.{key}`. A policy can therefore allow someone to create only keys that carry their team's tag.
`update` checks `iam:kms:update` a second time with the new tags, so a tag-scoped administrator cannot move a key out of
their own reach or into another team's.

Changing what a key looks like to policies never hands the caller rights on it. When tags change, or an alias is
added to a key, moved between keys or removed, every KMS action the caller may not take on the key as it is must stay
refused on the key as it would be. Otherwise someone who manages every key but may decrypt only one team's could
retag a key into that team, or remove the alias a deny names (`ArrayContains` on `resource.aliases`).

Alias names are a namespace of their own. Creating, moving or removing `alias/{name}` also needs `iam:kms:update` on
`iam/kms/alias/{name}` (the name is `resource.alias`). Someone who manages one key therefore cannot claim
`alias/prod/payments` and have others encrypt under their key. Grant alias prefixes explicitly, for example
`iam/kms/alias/sandbox/*`.

`list` evaluates `iam:kms:read` for each key and returns only the keys the caller may read. A tag-scoped reader sees
only their team's keys.

Sessions that view as someone else (impersonation) cannot use KMS at all. Callers from another tenant are refused
before any key is looked up, so they cannot tell which keys or aliases exist. An agent acting for a person under a
delegation that holds an action back (`confirm`) uses up one confirmation per call, as everywhere else.

## Managed keys

Keys another module created for its own use, or took over, carry `managedBy` (`pki` for a certificate authority's
signing key, `protection` for a data protection profile's key) and `managedId`. The KMS API refuses to encrypt,
decrypt, sign, generate data keys or MACs with them, or grant them (`KEY_MANAGED`, 409): only the module uses them, for
the decisions it makes. They stay visible, and can be tagged, rotated, disabled and deleted like any other key, which
is how their owner stops the module. Policies see `resource.managedBy`.

A key rotates on demand at most ten times a day (`RATE_LIMITED`); new key material is generated off the event loop.

## Grants

A **grant** allows one identity (a person, service account or agent) to perform named operations on one key: `read`,
`encrypt`, `decrypt`, `generate-data-key`, `sign`, `verify`, `generate-mac` or `verify-mac`. It lets a key's owner
hand a workload access to a single key without writing a policy.

```ts
await iam.api.keys.createGrant(ownerCredential, {
  tenantId,
  keyId: 'alias/customer-records',
  granteeId: billingWorker.id,
  operations: ['decrypt'],
  constraints: { encryptionContextSubset: { app: 'billing' } },
  expiresAt: Date.now() + 30 * 86400000,
});
```

Rules:

- A grant only passes on what its creator holds, for as long as they hold it. Each granted operation must be allowed
  to the creator by policy when the grant is made (grants they hold do not count), and **every use checks again** that
  the creator could make that very call now, with the same key attributes and encryption context. When the creator's
  binding expires, their role is removed, their just-in-time activation lapses, they are offboarded, or a deny is added
  (including one conditioned on the encryption context), their grants stop working at once. The creator is checked as
  a plain session of their own, without MFA or session tags, so policies that require those fail closed.
- Grants are made from a user session or API key acting in its own right, by an identity of the key's tenant, with
  `iam:kms:grant`. Assumed roles, session tokens and delegated sessions cannot create grants.
- A grant applies only when no policy decides the call and every boundary allows it. Explicit denies, tenant
  boundaries, permission boundaries, session policies and API-key scopes still apply.
- Grants serve user sessions and API keys acting in their own right. Assumed roles, session tokens, delegated agent
  sessions and impersonation never use them.
- Grants name identities only. To give a group key access, bind a role to the group; group membership then follows
  the group-authority rules that protect every other grant of access.
- `constraints.encryptionContextEquals` (exact match) and `encryptionContextSubset` (must contain these pairs) limit
  a grant to certain contexts. Constraints are allowed only on `encrypt`, `decrypt` and `generate-data-key` grants.
- Calls allowed through a grant record `grantId` in their audit event. A caller that reads a key through a `read`
  grant sees only its own grants in `listGrants`.
- `revokeGrant` needs `iam:kms:grant`. The grantee can give up its own grant with `retireGrant`, which needs no
  permission and is audited as `kms:grant-retire`.
- Grants can lapse (`expiresAt`). `iam.kms.maintain()` removes lapsed grants, and grants whose grantee or creator has
  been deleted.

## Disabling and deleting keys

- `disable` refuses every cryptographic call with the key (`KEY_STATE_INVALID`, 409) until `enable`. Everything
  encrypted under the key is unreadable in the meantime, which makes disabling a quick way to cut off access to data.
- `scheduleDeletion` (`waitingDays` 7 to 30, default 30; needs recent authentication) makes the key unusable and sets
  a `deletionDate`. Until that date, `cancelDeletion` brings the key back disabled.
- After the waiting period, `iam.kms.maintain()` destroys the key's material, versions, aliases and grants and records
  `kms:key-destroy`. **Nothing encrypted under the key can be decrypted again** (crypto-shredding), so check first
  with a disabled period that nothing still needs it.

## Audit

Every call writes an audit event with the action (for example `iam:kms:decrypt`) on resource `kms/{keyId}`
(`kms` for tenant-wide calls). The event records the key version, the encryption context, the algorithm, and the
grant that allowed the call, if any. It never records a plaintext, a key, or a signature. Denials are recorded like
any other denial. A call refused after it was authorized is recorded as a `deny` too, with `metadata.reason`:
`invalid-ciphertext` (a wrong context or a modified ciphertext, so repeated attempts show up in the trail),
`key-state` (a disabled key or one pending deletion), `key-managed` or `refused`. The two events of one `reEncrypt` share a
`reEncryptId`. `list` records one `iam:kms:read` event with the number of keys listed. Plugin `afterOperation` hooks
see which key and version served a call, but never plaintexts, data keys or signed tokens.

## How key material is protected

Key material is generated on the server with Node's `crypto`: random bytes for AES and HMAC keys, and PKCS#8 private
keys for ECDSA, Ed25519 and RSA. Each version is sealed with AES-256-GCM under the deployment `secret`, with the
key id and version as associated data, and stored in the `kmsKeyVersions` collection. Only asymmetric public keys are
stored in the clear.

When you rotate the deployment secret (`previousSecrets` and `iam.rotateSecrets()`, see
[Deployment](deployment.md)), KMS material is re-sealed with everything else. Keys, ciphertexts and signatures do not
change, and nobody has to re-encrypt anything.

Because the material is sealed under the deployment secret, anyone who has both the database and the secret can
recover the keys. Protect the secret as you would a master key.

## Scheduling

Run `iam.kms.maintain()` hourly next to the other scheduler jobs. It returns
`{ rotated, destroyed, grantsRemoved }`.

```ts
setInterval(() => void iam.kms.maintain(), 60 * 60 * 1000);
```

## Errors

| Code                       | Status | When                                                                             |
| -------------------------- | ------ | -------------------------------------------------------------------------------- |
| `KEY_STATE_INVALID`        | 409    | The key is disabled or pending deletion, or the state change does not apply      |
| `KEY_MANAGED`              | 409    | The key belongs to a certificate authority or a data protection profile          |
| `INVALID_CIPHERTEXT`       | 400    | Malformed or tampered ciphertext, wrong encryption context, or a different key   |
| `KEY_MATERIAL_UNAVAILABLE` | 500    | The deployment secret that sealed the key is no longer configured                |
| `NOT_FOUND`                | 404    | Unknown key, alias, version or grant in this tenant                              |
| `LIMIT_EXCEEDED`           | 409    | Too many keys, versions, aliases or grants                                       |
| `ACCESS_DENIED`            | 403    | No policy or grant allows the call, or a grant would exceed its creator's rights |
