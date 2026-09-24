# keys

Key management (KMS) gives each tenant cryptographic keys that never leave the server. Applications call `encrypt`,
`decrypt`, `sign`, `verify` and the MAC methods with a key, and every call is authorized by policy and written to the
audit trail. It works like AWS KMS: keys have versions and rotate without breaking existing data, aliases let
applications switch keys without a deploy, encryption contexts bind ciphertexts to their records, data keys make
envelope encryption possible, and grants hand one workload the use of one key. The repository guide is
`docs/key-management.md`.

## Key kinds

- `aes-256-gcm` (the default): `encrypt` and `decrypt` up to 4 KiB, `generateDataKey`, `reEncrypt`.
- `hmac-sha256`, `hmac-sha384`, `hmac-sha512`: `generateMac`, `verifyMac`, and HS256/384/512 tokens with `signJwt`.
- `ecc-p256`, `ecc-p384`, `ed25519`: ES256, ES384 and EdDSA signatures and tokens.
- `rsa-2048`, `rsa-3072`, `rsa-4096`: with `keyUsage: 'sign'`, PS256-PS512 and RS256-RS512; with
  `keyUsage: 'encrypt'`, RSA-OAEP with SHA-256 for small values.

A tenant keeps at most 1000 keys, and a key at most 1000 versions, 50 aliases and 50 grants.

## Resources and conditions

Keys are `iam/kms/{keyId}`. `create` and tenant-wide `listAliases` use `iam/kms`. Conditions can read
`resource.keySpec`, `resource.keyUsage`, `resource.keyState`, `resource.aliases`, `resource.createdBy`, each tag as
`resource.tags.{key}`, the call's encryption context as `resource.encryptionContext.{key}` and
`resource.encryptionContextKeys`, and the algorithm of signing, MAC and token calls as `resource.algorithm`. For
`create`, these attributes describe the requested key, so a policy can require that new keys carry the caller's
team tag. Sessions that view as someone else (impersonation) are refused.

## Managed keys

Keys a certificate authority signs with or a data protection profile encrypts with carry `managedBy` (`pki` or
`protection`, also `resource.managedBy`) and `managedId`. Every cryptographic call and `createGrant` refuse them with
`KEY_MANAGED` (409), so only the module that manages a key uses it. They can still be read, tagged, rotated, disabled
and scheduled for deletion.

## Ciphertexts and encryption contexts

A ciphertext looks like `kms1.{keyId}.{version}.{t|b}.{payload}`. It names its key and version, so `decrypt` needs
only the ciphertext and the encryption context. The encryption context is up to 16 non-secret string pairs that are
authenticated with the ciphertext. Decrypting with a different context, or decrypting a modified ciphertext, fails
with `INVALID_CIPHERTEXT`, and that failure is audited as a denied decrypt.

## Grants

A grant lets one identity (a person, service account or agent) perform named operations on one key: `read`,
`encrypt`, `decrypt`, `generate-data-key`, `sign`, `verify`, `generate-mac` or `verify-mac`. The operations can be
limited to certain encryption contexts, and a grant can have an end date. A grant applies only when no policy decides
the call and every boundary, explicit deny, session policy and API-key scope allows it. Every use also checks that the
grant's creator could make the same call now, so a grant stops working when its creator loses the access it passed
on. Grants serve user sessions and API keys acting in their own right. Assumed roles, session tokens, delegated agent
sessions and impersonation never use them.

## Aliases

Adding, moving or removing an alias changes `resource.aliases`, so like a change of tags it must not give the caller
any KMS action on the keys involved that they are refused now. Alias names are authorized on their own: creating,
moving or removing `alias/{name}` needs `iam:kms:update` on
`iam/kms/alias/{name}` as well as on the key, so managing one key does not let anyone claim a name others encrypt
under.

## create

Creates a key, optionally with an alias, tags, a description and automatic rotation.

- **Permission:** `iam:kms:create` on `iam/kms`. The request's spec, usage and tags are the resource attributes.
- **Audited as:** `iam:kms:create` (metadata: `keyId`, `keySpec`, `keyUsage`, `alias`).
- **Errors:** `INVALID_INPUT` for an unknown `keySpec`, a missing or wrong `keyUsage`, invalid tags, a malformed alias
  or a `rotationPeriodDays` outside 1 to 3650; `CONFLICT` when the alias is taken; `LIMIT_EXCEEDED` past 1000 keys.

```ts
const key = await iam.api.keys.create(credential, {
  tenantId,
  alias: 'alias/customer-records',
  tags: { team: 'payments' },
  rotationPeriodDays: 365,
});
```

## list

The tenant's keys that the caller may read, newest first, optionally filtered by `state` or `keyUsage`.

- **Permission:** `iam:kms:read`, evaluated for each key, so a reader limited by tags sees only matching keys.
- **Audited as:** one `iam:kms:read` event on `kms` (metadata: `listed`).

## get

One key by id or alias: its spec, usage, state, current version, tags, aliases, algorithms and rotation schedule.
Never its material.

- **Permission:** `iam:kms:read` on `iam/kms/{keyId}`, or a grant that allows `read`.
- **Errors:** `NOT_FOUND` for an unknown key or alias in this tenant.

## listVersions

The key's versions, newest first, with their origin (`create`, `rotate` or `automatic`) and, for asymmetric keys, a
fingerprint of the public key.

- **Permission:** `iam:kms:read`.

## update

Changes the description, replaces the tags, or sets or clears (`null`) the automatic rotation period.

- **Permission:** `iam:kms:update`. When the tags change, `iam:kms:update` is evaluated again with the new tags, so a
  tag-scoped administrator cannot move a key out of their reach or into another team's. New tags must also not give
  the caller any KMS action on the key that the current tags refuse them.
- **Audited as:** `iam:kms:update` (metadata: `tags`, `rotationPeriodDays`).
- **Errors:** `ACCESS_DENIED` when the new tags would take the key out of the caller's reach or open it to them;
  `KEY_STATE_INVALID` for a key pending deletion.

## enable

Enables a disabled key.

- **Permission:** `iam:kms:update`.
- **Errors:** `KEY_STATE_INVALID` for a key pending deletion (cancel the deletion first).

## disable

Disables a key. Every cryptographic call with it is refused with `KEY_STATE_INVALID` until it is enabled again, so
data encrypted under it cannot be read in the meantime.

- **Permission:** `iam:kms:update`.
- **Errors:** `KEY_STATE_INVALID` for a key pending deletion.

## rotate

Creates a new version on demand. The new version encrypts, signs and computes MACs from now on, and older versions
keep decrypting and verifying.

- **Permission:** `iam:kms:update`.
- **Audited as:** `iam:kms:update` (metadata: `rotated`, `keyVersion`).
- **Errors:** `KEY_STATE_INVALID` unless the key is enabled; `RATE_LIMITED` after ten on-demand rotations of the key
  within a day; `LIMIT_EXCEEDED` past 1000 versions.

## scheduleDeletion

Schedules the key's destruction after a waiting period of 7 to 30 days (30 by default). The key is unusable while it
waits. Afterwards the scheduler job `iam.kms.maintain()` destroys its material, aliases and grants, and nothing
encrypted under it can be decrypted again.

- **Permission:** `iam:kms:delete`, with recent authentication.
- **Audited as:** `iam:kms:delete` (metadata: `deletionDate`); the destruction as `kms:key-destroy`.
- **Errors:** `KEY_STATE_INVALID` when the key is already pending deletion; `RECENT_AUTH_REQUIRED`.

## cancelDeletion

Cancels a scheduled deletion. The key comes back disabled.

- **Permission:** `iam:kms:delete`.
- **Errors:** `KEY_STATE_INVALID` unless the key is pending deletion.

## createAlias

Names a key `alias/{name}`. Names use letters, digits, slashes, underscores and hyphens and are unique within the
tenant.

- **Permission:** `iam:kms:update` on the key and on `iam/kms/alias/{name}`.
- **Errors:** `CONFLICT` when the alias is taken; `LIMIT_EXCEEDED` past 50 aliases on the key; `INVALID_INPUT` for a
  malformed name, or when `keyId` is itself an alias.

## updateAlias

Points an alias at another key of the same kind and usage, so applications that name the alias switch keys without
a deploy.

- **Permission:** `iam:kms:update` on the new key, on the key the alias named until now, and on
  `iam/kms/alias/{name}`.
- **Audited as:** `iam:kms:update` (metadata: `alias`, `previousKeyId`).
- **Errors:** `INVALID_INPUT` when the keys differ in kind or usage; `NOT_FOUND` for an unknown alias.

## deleteAlias

Removes an alias. The key stays.

- **Permission:** `iam:kms:update` on the key the alias names and on `iam/kms/alias/{name}`.

## listAliases

Every alias in the tenant, or the aliases of one key (`keyId`), sorted by name.

- **Permission:** `iam:kms:read` on `iam/kms`, or on the key when `keyId` is given.

## createGrant

Allows an identity to perform named operations on one key, optionally until `expiresAt` and, for encryption
operations, only with a matching encryption context (`constraints.encryptionContextEquals` or
`encryptionContextSubset`).

- **Permission:** `iam:kms:grant` from a user session or API key of the key's tenant acting in its own right, and the
  caller must be allowed each granted operation by policy. Grants the caller holds do not count, and each use of the
  grant checks the creator's access again, so a grant never passes on more than its creator has.
- **Audited as:** `iam:kms:grant` (metadata: `grantId`, `granteeType`, `granteeId`, `operations`, `constraints`,
  `expiresAt`). Calls allowed through the grant record its `grantId`.
- **Errors:** `INVALID_INPUT` for operations the key's usage does not support, constraints on operations without an
  encryption context, or a `granteeType` other than `identity`; `ACCESS_DENIED` when the caller does not hold an
  operation or acts through a role, token or delegated session; `NOT_FOUND` for an unknown identity; `LIMIT_EXCEEDED`
  past 50 grants.

```ts
await iam.api.keys.createGrant(ownerCredential, {
  tenantId,
  keyId: 'alias/customer-records',
  granteeId: billingWorker.id,
  operations: ['decrypt'],
  constraints: { encryptionContextSubset: { app: 'billing' } },
});
```

## listGrants

The key's grants, newest first, each with `active` (not lapsed).

- **Permission:** `iam:kms:read`.

## revokeGrant

Revokes a grant.

- **Permission:** `iam:kms:grant` on the grant's key.

## retireGrant

Gives up a grant made to the caller's own identity. It needs no permission, so a workload can drop access it no
longer uses.

- **Audited as:** `kms:grant-retire` (metadata: `grantId`).
- **Errors:** `ACCESS_DENIED` for anyone but the grantee identity.

## publicKey

The public key of an asymmetric key version (the current one by default), as SPKI PEM and as a JWK whose `kid` is
`{keyId}.{version}`. Anyone holding it can verify signatures without calling IAM. RSA encryption keys bind a label to
their ciphertexts, so values encrypted offline with the public key are not KMS ciphertexts.

- **Permission:** `iam:kms:read`.
- **Errors:** `INVALID_INPUT` for AES and HMAC keys.

## jwks

Every version's public key of an asymmetric key, as a JWK Set for verifying tokens signed with `signJwt`.

- **Permission:** `iam:kms:read`.

## encrypt

Encrypts up to 4 KiB (`plaintext` as UTF-8 text, or `plaintextBase64`) with the key's current version, bound to the
optional encryption context. RSA encryption keys accept what their modulus allows (190 bytes for 2048 bits).

- **Permission:** `iam:kms:encrypt`, or a grant.
- **Audited as:** `iam:kms:encrypt` (metadata: `keyVersion`, `encryptionContext`).
- **Errors:** `KEY_STATE_INVALID` for a disabled key or a key pending deletion; `INVALID_INPUT` for a key that is not
  an encryption key or a plaintext that is too long.

```ts
const { ciphertext } = await iam.api.keys.encrypt(credential, {
  tenantId,
  keyId: 'alias/customer-records',
  plaintext: 'card on file: 4242',
  encryptionContext: { customer: 'cus_123' },
});
```

## decrypt

Decrypts a ciphertext from `encrypt`, `generateDataKey` or `reEncrypt`, given the same encryption context. Text comes
back as `plaintext`, bytes as `plaintextBase64`. Passing `keyId` additionally insists on that key.

- **Permission:** `iam:kms:decrypt` on the key the ciphertext names, or a grant.
- **Audited as:** `iam:kms:decrypt` (metadata: `keyVersion`, `encryptionContext`). A decryption that fails after the
  call was authorized is recorded as a `deny` with `reason: 'invalid-ciphertext'`.
- **Errors:** `INVALID_CIPHERTEXT` for a malformed or modified ciphertext, a different encryption context, or a
  ciphertext of another key; `KEY_STATE_INVALID`; `NOT_FOUND` when the key has been destroyed.

## reEncrypt

Decrypts a ciphertext and encrypts it again under another key or context, without the plaintext leaving the server.

- **Permission:** `iam:kms:decrypt` on the source key and `iam:kms:encrypt` on the destination key.
- **Audited as:** both `iam:kms:decrypt` and `iam:kms:encrypt`.

## generateDataKey

Returns a fresh random data key of 16, 24, 32 (default) or 64 bytes for encrypting large data locally: the plaintext
key to use and discard, and its ciphertext under the KMS key to store beside the data. With `includePlaintext: false`
only the ciphertext comes back.

- **Permission:** `iam:kms:generate-data-key`, or a grant. Decrypting the stored data key later needs
  `iam:kms:decrypt`.
- **Audited as:** `iam:kms:generate-data-key` (metadata: `keyVersion`, `bytes`, `encryptionContext`).

## sign

Signs a message (`message` or `messageBase64`, up to 64 KiB) with the key's current version. `algorithm` defaults to
the key's first (ES256, ES384, EdDSA, or PS256 for RSA). ECDSA signatures are DER unless `format: 'jose'`.

- **Permission:** `iam:kms:sign`, or a grant. `resource.algorithm` names the algorithm.
- **Audited as:** `iam:kms:sign` (metadata: `keyVersion`, `algorithm`).

## verify

Checks a signature from `sign` with the given `keyVersion` (the current one by default). Returns `{ valid }`: a
mismatch is not an error.

- **Permission:** `iam:kms:verify`, or a grant.
- **Audited as:** `iam:kms:verify` (metadata: `keyVersion`, `algorithm`, `valid`).

## generateMac

Computes an HMAC of a message with the key's current version and returns it as base64url.

- **Permission:** `iam:kms:generate-mac`, or a grant.

## verifyMac

Checks a MAC in constant time with the given `keyVersion` (the current one by default). Returns `{ valid }`.

- **Permission:** `iam:kms:verify-mac`, or a grant.

## signJwt

Signs a JWT with a signing key or a MAC key. The header is `{ alg, kid, typ }` with `kid` = `{keyId}.{version}` (the
same `kid` as in `jwks`). `iat` is added when absent, and `exp` comes from `expiresInSeconds` (1 second to 1 year).

- **Permission:** `iam:kms:sign` for signing keys, `iam:kms:generate-mac` for MAC keys. Policies also see
  `resource.jwt` (true), `resource.jwt.typ`, `resource.jwt.sub`, `resource.jwt.iss` and `resource.jwt.aud` (or
  `resource.jwt.audiences`), so they can limit which tokens a caller mints, or allow tokens but not raw `sign`.
- **Audited as:** that action (metadata: `keyVersion`, `algorithm`, `jwt`).

## verifyJwt

Verifies a JWT made with a key. The `kid` selects the version, `alg` must be one of the key's algorithms (so `none`
and algorithm swaps fail), `exp` and `nbf` are checked with `clockToleranceSeconds` (60 by default), and `audience`
and `issuer` are checked when given. Tokens with a `crit` header, or an `exp` or `nbf` that is not a number, are
refused. Returns `{ valid: true, claims, header }` or `{ valid: false, reason }` with `reason` one of `signature`,
`expired`, `not-yet-valid`, `audience`, `issuer`, `algorithm`, `header` or `claims`.

- **Permission:** `iam:kms:verify` for signing keys, `iam:kms:verify-mac` for MAC keys.
- **Errors:** `INVALID_INPUT` for a token that is not a compact JWS, or without a KMS `kid` and no `keyId`.
