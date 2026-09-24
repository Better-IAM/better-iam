# Verifiable credentials

Every organization can issue **verifiable credentials**: signed statements about its people, such as an employee badge,
that people keep in a digital wallet and show to anyone who asks. The person discloses only what a verifier needs, for
example "works at Acme" without their email address. The verifier checks the signature and the credential's current
status without calling back to the organization's apps.

Better IAM issues **SD-JWT VCs**, the IETF format behind the EU digital identity wallet and OpenID4VC ecosystems:

- **Selective disclosure** (SD-JWT, RFC 9901). Each claim can be revealed or withheld per presentation.
- **Holder binding.** Credentials are bound to a key the holder proved they own, so a copied credential is useless.
- **Revocation and suspension** through an IETF **Token Status List**. It is a compressed bitstring the issuer signs
  and serves.
- **Wallet issuance** over **OpenID4VCI** (pre-authorized code flow, with an optional PIN), plus a direct API for
  apps that embed their own wallet.
- **Verification** of presentations: offline with the issuer's keys, or through `iam.verifiableCredentials.verify`.

Turn it on with the `verifiableCredentials` option:

```ts
const iam = betterIam({
  // ...
  verifiableCredentials: true, // or { maxLifetimeMs, statusListSize, offerLifetimeMs, ... }
});
```

| Option                 | Default   | Meaning                                                               |
| ---------------------- | --------- | --------------------------------------------------------------------- |
| `maxLifetimeMs`        | 365 days  | The longest lifetime any credential type may set (5 min – 5 years)    |
| `statusListSize`       | 65536     | Entries per status list (a list is used up to half full)              |
| `offerLifetimeMs`      | 10 min    | How long a wallet offer can be redeemed                               |
| `statusListLifetimeMs` | 24 hours  | How long a signed status list token is valid                          |
| `statusListTtlSeconds` | 300       | How long verifiers may cache it (`ttl`, and `Cache-Control`)          |
| `recordRetentionDays`  | 30        | How long issued-credential records stay after the credential expired |

Each tenant is an issuer. Its identifier, and the base of its wallet endpoints, is
`{origin}{basePath}/vc/{tenantId}`, for example `https://iam.example.com/api/iam/vc/ten_123`.

## Credential types

A credential type says which claims a credential carries and where each value comes from. Administrators manage types
with `iam:vc:manage`:

```ts
await iam.api.verifiableCredentials.createType(admin, {
  tenantId,
  name: 'employee',
  displayName: 'Acme employee',
  description: 'Works at Acme',
  claims: [
    { name: 'email', source: 'email', label: 'Email' },
    { name: 'name', source: 'name', selective: false }, // always shown
    { name: 'organization', source: 'tenantName', selective: false },
    { name: 'department', source: 'department' },
    { name: 'teams', source: 'teams' },
    { name: 'title', source: 'attribute:title', required: true },
    { name: 'clearance', source: 'static', value: 'standard' },
  ],
  lifetimeMs: 90 * 86_400_000, // default 30 days
  requireMfa: true,
  backgroundColor: '#0b2545',
  textColor: '#ffffff',
});
```

| Source                                            | Value                                                  |
| ------------------------------------------------- | ------------------------------------------------------ |
| `email`, `emailVerified`, `name`, `identityId`, `kind` | The person's account                              |
| `tenantId`, `tenantName`                          | The organization                                       |
| `teams`                                           | Names of the [teams](teams-and-departments.md) they are on |
| `department`                                      | Their department's name                                |
| `attribute:{name}`                                | A declared identity attribute (`permissions.identityAttributes`) |
| `static`                                          | A fixed `value` (at most 2 KiB of JSON)                |

A claim is selectively disclosable unless it has `selective: false`. A claim whose value is missing is left out, unless
it is `required`, in which case issuing fails with `CLAIM_UNAVAILABLE`. Claim names that SD-JWT VC reserves (`iss`,
`sub`, `iat`, `nbf`, `exp`, `cnf`, `vct`, `status`, …) are refused. The type identifier (`vct`) defaults to
`{issuer}/types/{name}`, which serves SD-JWT VC type metadata (display name, colors, claim labels). A type can pass its
own `vct` instead, such as a shared schema URL. It may not be one under another organization's issuer on this
deployment (`INVALID_INPUT`), since verifiers match on it.

`updateType` changes the display, claims, lifetime, `requireMfa` or `enabled`; the name and `vct` never change.
`deleteType` is refused while valid credentials of the type exist: disable the type, or revoke them first.

## Who gets credentials

People get credentials for themselves when policies allow `vc:request` on `credential-type/{name}`. The attributes
`name`, `vct` and `requireMfa` are available to conditions:

```json
{
  "effect": "allow",
  "actions": ["vc:request"],
  "resources": ["credential-type/employee"],
  "conditions": { "StringEquals": { "principal.department": "Engineering" } }
}
```

A self-service request is also refused:

- from an impersonation ("view as") session;
- from an agent acting for the person ([delegated session](AGENTS.md#delegation-acting-on-a-persons-behalf)), which
  would otherwise bind the person's credential to a key of its own;
- from a principal of another organization, including the platform root override;
- without an MFA session when the type has `requireMfa` (`MFA_REQUIRED`);
- for a disabled type (`TYPE_DISABLED`).

A refusal is audited as a denied `vc:request`. `available` lists the types the caller may request right now.

A self-service credential never outlives the access that allowed it. When `vc:request` comes from a time-limited grant
(an expiring binding or group membership, a
[just-in-time activation](policies.md#eligible-bindings-just-in-time-access), an access window), the credential ends
with it. Credentials requested from an assumed role or temporary credentials end with that session.
When the grant ends within a minute, the request fails with `ACCESS_EXPIRING`.

Administrators with `iam:vc:issue` can offer a credential to someone else (`createOffer` with `identityId`). The person
redeems the offer in their wallet, which binds the credential to the wallet's key.

## Issuing to a wallet (OpenID4VCI)

`createOffer` returns an OpenID4VCI credential offer with a pre-authorized code. Show `offerUri` as a QR code, or open it
on the phone:

```ts
const offer = await iam.api.verifiableCredentials.createOffer(session, {
  tenantId,
  type: 'employee',
  txCode: true, // the wallet asks for a 6-digit PIN
});
// offer.offerUri: 'openid-credential-offer://?credential_offer=%7B...'
// offer.txCode: '482913'  (show it separately from the QR code)
```

The wallet then talks to the issuer's endpoints, which are mounted next to the HTTP API with no extra setup:

| Endpoint                                                      | Serves                                           |
| ------------------------------------------------------------- | ------------------------------------------------ |
| `GET /.well-known/openid-credential-issuer{basePath}/vc/{tenant}` | Credential issuer metadata (types, display)   |
| `GET /.well-known/oauth-authorization-server{basePath}/vc/{tenant}` | Token endpoint metadata                     |
| `GET /.well-known/jwt-vc-issuer{basePath}/vc/{tenant}`        | The issuer's public keys (SD-JWT VC)             |
| `POST {issuer}/token`                                         | Pre-authorized code (and PIN) → access token      |
| `POST {issuer}/nonce`                                         | A proof nonce (`c_nonce`)                        |
| `POST {issuer}/credential`                                    | The credential, bound to the key in the proof    |
| `GET {issuer}/types/{name}`                                   | SD-JWT VC type metadata                          |
| `GET {issuer}/status/{listId}`                                | The Token Status List (`application/statuslist+jwt`) |
| `GET {issuer}/jwks.json`                                      | The issuer's public keys                         |

When the HTTP handler is mounted inside a framework route (such as a Next.js catch-all at `/api/iam`), forward
`/.well-known/openid-credential-issuer/*`, `/.well-known/oauth-authorization-server/*` and `/.well-known/jwt-vc-issuer/*`
to `iam.handler` as well. The `{issuer}/...` endpoints are under the base path already.

Each offer's code works once and expires after `offerLifetimeMs`. A token request without the PIN is answered
`invalid_request` and does not count as a guess. Wrong PINs are audited as denied `vc:offer:redeem`, and five end the
offer. The access token lasts five minutes and yields one credential. The wallet's proof (`openid4vci-proof+jwt`, with
its public key in the `jwk` header) must name the issuer as `aud` and carry a fresh nonce, which works once. Nonces are
signed rather than stored, so handing them out writes nothing. For self-service offers, policy and MFA are decided
again when the wallet redeems the offer, and the credential ends with the grants that allow it. Taking `vc:request`
away in the meantime stops the offer, audited as a denied `vc:offer:redeem`. The credential records the offer, and the
administrator who made an offer for someone is recorded as its `issuedBy`.

## Issuing through the API

Apps that hold the key themselves (a mobile app with its own wallet, a test harness) call `request` with a proof:

```ts
const { nonce } = await iam.api.verifiableCredentials.nonce({ tenantId });
const proof = await new SignJWT({ aud: issuer, nonce, iat: Math.floor(Date.now() / 1000) })
  .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: publicJwk })
  .sign(privateKey);
const { credential } = await iam.api.verifiableCredentials.request(session, { tenantId, type: 'employee', proof });
// credential: '<issuer-signed JWT>~<disclosure>~<disclosure>~'
```

Holder keys may be ES256, ES384 or EdDSA (Ed25519). Issuing is audited as `vc:credential:issue`, with the type, the
holder key's thumbprint and the claim names, never the values. A credential never outlives the person's scheduled
account expiry.

## Presenting and verifying

A holder presents a credential with only the claims a verifier needs, plus a key-binding JWT over the verifier's
audience and nonce. `presentSdJwt` (exported by the server package) does this for Node wallets and tests:

```ts
import { presentSdJwt } from '@better-iam/server';

const presentation = await presentSdJwt(credential, {
  disclose: ['email'],
  holderKey: privateKey,
  alg: 'ES256',
  audience: 'https://shop.example',
  nonce: challengeFromTheVerifier,
});
```

A verifier running next to the deployment calls `iam.verifiableCredentials.verify`. Remote verifiers call the public
`verifiableCredentials.verify` route, which reports instead of throwing:

```ts
const result = await iam.api.verifiableCredentials.verify({
  presentation,
  audience: 'https://shop.example',
  nonce: challengeFromTheVerifier,
});
if (result.valid) result.claims.email; // 'alice@acme.test'; undisclosed claims are absent
else result.reason; // 'revoked', 'suspended', 'wrong-nonce', 'bad-disclosure', ...
```

`audience` and `nonce` are required (`INVALID_INPUT` without them): without them, a presentation captured by one
verifier would verify for any other. Use a fresh nonce per presentation, and remember the ones you accepted. The result's
`keyBinding` (`audience`, `nonce`, `issuedAt`) is there for that bookkeeping. `iam.verifiableCredentials.verify` accepts
`requireKeyBinding: false` for credentials checked without a holder, such as an issuer-side audit.

A verification checks, in order:

1. The issuer's signature, with one of that tenant's current or previous keys (by `kid`).
2. The validity times.
3. That every disclosure matches a digest the issuer signed, exactly once. A disclosure can never overwrite a signed
   or reserved claim.
4. The key-binding JWT: the holder key from `cnf.jwk`, the audience, the nonce, freshness (5 minutes), and `sd_hash`
   over the exact presentation.
5. The credential's entry in the status list.

Verifiers elsewhere can do the same offline with any SD-JWT VC library. They fetch the keys from
`/.well-known/jwt-vc-issuer{basePath}/vc/{tenantId}` and the status list from the URI in the credential's
`status.status_list`. `verifySdJwt`, `readStatusList` and `statusAt` are exported for Node verifiers.

## Revocation

`revoke` ends a credential for good. `suspend` and `reinstate` turn it off and on again (a lost phone). Holders may
revoke their own credentials from their own session. Delegated sessions and credentials narrowed by a session policy
go through `iam:vc:revoke` like anyone else's, and `mine` refuses delegated sessions. Each credential has a random, never-reused index in a
status list with two bits per entry (0 valid, 1 revoked, 2 suspended), so verifiers see changes within the list's
`ttl`. Random indexes keep a credential's position from revealing when it was issued.

The scheduler job `iam.verifiableCredentials.sweep()` (hourly) revokes the credentials of people who are no longer
active members (reason `identity-inactive`). It also re-decides `vc:request` for self-service credentials, with the MFA
state of the session that obtained them, and revokes those no longer allowed (`access-changed`). A suspended
organization's credentials already fail verification, so the sweep leaves them for its reinstatement.

## Issuer keys

Each tenant signs with an ES256 key created with its first credential type, sealed under the deployment secret and
re-sealed by `iam.rotateSecrets()`. `rotateKey` starts signing with a new key. The old one stays published as `previous`,
so its credentials keep verifying. `retireKey` removes a previous key from the published keys, after which its
credentials no longer verify. It is refused while valid credentials signed by it exist, unless `force`, which revokes
them.

## API

| Method                                                         | Access                                     |
| -------------------------------------------------------------- | ------------------------------------------ |
| `createType`, `updateType`, `deleteType`, `rotateKey`, `retireKey` | `iam:vc:manage`                        |
| `status`, `getType`, `listTypes`, `listIssued`, `listKeys`     | `iam:vc:read`                              |
| `createOffer` for someone else                                 | `iam:vc:issue`                             |
| `revoke` (someone else's), `suspend`, `reinstate`              | `iam:vc:revoke`                            |
| `request`, `createOffer` for yourself, `available`, `mine`, `revoke` (own) | a session; `vc:request` decides for requests |
| `nonce`, `verify`, `issuerMetadata`                            | public                                     |

Errors: `FEATURE_DISABLED`, `TYPE_DISABLED`, `IDENTITY_INACTIVE`, `CLAIM_UNAVAILABLE`, `INVALID_PROOF`,
`INVALID_NONCE`, `MFA_REQUIRED`, `IMPERSONATION_RESTRICTED`, `ACCESS_EXPIRING`, `RESOURCE_IN_USE`,
`INVALID_TRANSITION`. The wallet endpoints answer with OAuth-style errors (`invalid_request`, `invalid_grant`,
`invalid_token`, `invalid_proof`, `invalid_nonce`, `unknown_credential_configuration`, `access_denied`). Their request
bodies are limited (8 KiB for the token endpoint, 16 KiB for the credential endpoint).

Audit events: `vc:credential:issue`, `vc:credential:revoke` (own and sweep), `vc:offer:create`, denied
`vc:offer:redeem` (wrong PIN, lockout, access changed), denied `vc:request`, and the `iam:vc:*` administration
operations. The public metadata, keys, type and status list endpoints only read.
