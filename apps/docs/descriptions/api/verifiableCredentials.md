# verifiableCredentials

Every organization can issue verifiable credentials: SD-JWT VCs (IETF SD-JWT-based Verifiable Credentials) that people
keep in digital wallets and present with only the claims a verifier needs. Credentials are bound to a key the holder
proved they own, and they are revoked or suspended through an IETF Token Status List that verifiers read. Wallets get
credentials over OpenID4VCI from endpoints mounted at `{basePath}/vc/{tenantId}`. Apps can call `request` directly. The
group exists when the deployment sets the `verifiableCredentials` option; otherwise every method fails with
`FEATURE_DISABLED`. The guide is
[Verifiable credentials](https://github.com/Better-IAM/better-iam/blob/main/docs/verifiable-credentials.md).

## status

The issuer at a glance: its identifier and metadata URL, the published keys, the number of credential types, issued
credentials by state (valid, suspended, revoked, expired), and status lists.

- **Permission:** `iam:vc:read` on `iam/vc/issuer`.

## createType

Defines a credential type: a `name`, a `displayName` and description for wallets, card colors, a lifetime (default 30
days, at most the deployment's `maxLifetimeMs`), `requireMfa`, and 1 to 32 `claims`. Each claim takes its value from a
`source`: `email`, `emailVerified`, `name`, `identityId`, `kind`, `tenantId`, `tenantName`, `teams`, `department`, a
declared identity attribute (`attribute:{name}`) or a `static` value. It is selectively disclosable unless `selective:
false`, and left out when missing unless `required`. The `vct` defaults to `{issuer}/types/{name}`; a custom one may not
sit under another organization's issuer on this deployment. The first type also creates the tenant's issuer key.

- **Permission:** `iam:vc:manage` on `iam/vc/types/{name}`.
- **Errors:** `CONFLICT` for a name in use; `INVALID_INPUT` for reserved or repeated claim names, unknown sources,
  invalid colors, or a `vct` under another organization's issuer.

## updateType

Changes a type's display, claims, lifetime, `requireMfa` or `enabled`. The name and `vct` never change.

- **Permission:** `iam:vc:manage` on `iam/vc/types/{name}`.

## deleteType

Deletes a type and its pending offers.

- **Permission:** `iam:vc:manage` on `iam/vc/types/{name}`.
- **Errors:** `RESOURCE_IN_USE` while valid credentials of the type exist.

## getType

One credential type.

- **Permission:** `iam:vc:read` on `iam/vc/types/{name}`.

## listTypes

Every credential type of the tenant, by name.

- **Permission:** `iam:vc:read` on `iam/vc/types`.

## available

The enabled types the caller may request for themselves right now: `vc:request` allowed on `credential-type/{name}`,
MFA when the type asks, and not in a "view as" session or a delegated agent session. No permission needed.

## nonce

A single-use proof nonce (`c_nonce`) for the tenant's issuer, valid five minutes. Nonces are signed rather than stored,
so handing one out writes nothing; a proof spends its nonce. Public.

## request

Issues a credential of `type` to the caller, bound to the key in `proof`. The proof is an `openid4vci-proof+jwt` with
the holder's public key in its `jwk` header, the issuer URL as `aud`, and a nonce from `nonce`. Holder keys may be
ES256, ES384 or EdDSA. Returns the SD-JWT VC and its record. The credential ends at the type's lifetime, the person's
scheduled account expiry, or the end of the time-limited grant that allows `vc:request` (an expiring binding or
membership, a just-in-time activation, an access window), whichever comes first. From an assumed role or temporary
credentials it ends with that session.

- **Permission:** a session, not a delegated agent session; `vc:request` on `credential-type/{type}`, and MFA when the
  type requires it.
- **Audited as:** `vc:credential:issue` (type, holder key thumbprint, claim names); a refusal as a denied `vc:request`.
- **Errors:** `ACCESS_DENIED`; `MFA_REQUIRED`; `TYPE_DISABLED`; `IMPERSONATION_RESTRICTED`; `INVALID_PROOF`;
  `INVALID_NONCE`; `CLAIM_UNAVAILABLE` when a required claim has no value; `ACCESS_EXPIRING` when the grant that
  allows it ends within a minute.

## createOffer

An OpenID4VCI credential offer with a pre-authorized code, and its `openid-credential-offer://` link for a wallet to
scan. It is for the caller (`vc:request`, like `request`) or, with `identityId`, for someone else (`iam:vc:issue`).
`txCode: true` adds a 6-digit PIN the wallet asks for; give it to the person separately. The code works once and
expires after the deployment's `offerLifetimeMs`. A token request without the PIN does not count as a guess; five wrong
PINs end the offer. For self-service offers, policy and MFA are decided again when the wallet redeems the offer, and
the credential ends with the grants that allow it. An administrator's offer records them as the credential's
`issuedBy`.

- **Audited as:** `vc:offer:create`; refused redemptions (wrong PIN, lockout, access changed) as a denied
  `vc:offer:redeem`.
- **Errors:** as `request`; `IDENTITY_INACTIVE` for someone who is not an active member.

## mine

The caller's own credentials in the tenant, newest first (the last 100), with their state. Refused for delegated agent
sessions (`ACCESS_DENIED`).

## listIssued

Issued credentials, newest first, by `type`, `identityId` or `state` (`valid`, `suspended`, `revoked`, `expired`), with
`limit` (at most 500) and `offset`. Records hold claim names, never values.

- **Permission:** `iam:vc:read` on `iam/vc/credentials`.

## revoke

Revokes a credential for good: its status list entry becomes invalid. Holders may revoke their own credentials from
their own session; delegated agent sessions and credentials narrowed by a session policy, and anyone revoking someone
else's, need the permission.

- **Permission:** none for your own from your own session; otherwise `iam:vc:revoke` on `iam/vc/credentials/{id}`.
- **Audited as:** `vc:credential:revoke` (own) or `iam:vc:revoke`.
- **Errors:** `INVALID_TRANSITION` for a credential already revoked.

## suspend

Suspends a valid credential (a lost phone). Verifiers see it as suspended until `reinstate`.

- **Permission:** `iam:vc:revoke` on `iam/vc/credentials/{id}`.
- **Errors:** `INVALID_TRANSITION` unless the credential is valid.

## reinstate

Lifts a suspension.

- **Permission:** `iam:vc:revoke` on `iam/vc/credentials/{id}`.
- **Errors:** `INVALID_TRANSITION` unless the credential is suspended.

## listKeys

The issuer's signing keys, oldest first: `active`, `previous` (still published, so its credentials verify) and
`retired`.

- **Permission:** `iam:vc:read` on `iam/vc/keys`.

## rotateKey

Starts signing with a new ES256 key. The current one stays published as `previous`.

- **Permission:** `iam:vc:manage` on `iam/vc/keys`.

## retireKey

Stops publishing a previous key, after which credentials it signed no longer verify.

- **Permission:** `iam:vc:manage` on `iam/vc/keys`.
- **Errors:** `RESOURCE_IN_USE` while valid credentials it signed exist, unless `force: true`, which revokes them;
  `INVALID_TRANSITION` for the active key.

## verify

Verifies a presentation of a credential this deployment issued. It checks the issuer's signature (the tenant's current
or previous keys), validity times, every disclosure against the signed digests, the key-binding JWT (`audience`,
`nonce`, freshness, `sd_hash`) and the credential's status. Returns `{ valid: true, claims, disclosed, type, ... }`, or
`{ valid: false, reason }` with reasons such as `revoked`, `suspended`, `wrong-audience`, `wrong-nonce`,
`bad-disclosure` or `unknown-issuer`. `audience` and `nonce` are required (`INVALID_INPUT` without them), since a
presentation captured by one verifier would otherwise verify for any other; the result's `keyBinding` (`audience`,
`nonce`, `issuedAt`) is there for your own record of accepted nonces. Public.

## issuerMetadata

The tenant's OpenID4VCI credential issuer metadata: endpoints, and every enabled type with its format (`dc+sd-jwt`),
`vct`, binding methods, proof algorithms and wallet display. The same document is served at
`/.well-known/openid-credential-issuer{basePath}/vc/{tenantId}`. Public.
