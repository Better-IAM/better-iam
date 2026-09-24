# Shared Signals receiver

An organization's identity provider often knows things about its people that Better IAM does not: a password turned
up in a breach, the security team ended all of someone's sessions, a sign-in looks high risk, an account was disabled.
The OpenID Shared Signals Framework (SSF 1.0) lets the provider send these facts as signed Security Event Tokens (SETs,
RFC 8417) using the CAEP and RISC event types. Better IAM receives them:

1. Each organization registers its providers as **signal sources** in the `signals` API group. A source records the
   issuer, the keys its SETs are signed with, the audiences they are addressed to, and how they arrive.
2. Events arrive by **push** (RFC 8935: the provider posts to a URL the source is given) or by **poll** (RFC 8936: the
   scheduler job `iam.signals.poll()` fetches them from the provider).
3. Each SET is **verified** against the source's keys and settings, and **deduplicated** on its issuer and `jti`.
4. Its subject is **matched** to a person of the source's organization, through federation links, SCIM-provisioned
   users, or email addresses at verified domains.
5. The event is **recorded** (`signals.listEvents`, kept for 90 days) and **audited** as `signal:received`, which
   threat detection reads.
6. When the source asks for it for that event type, the person's **sessions end** at once. The receiver does nothing
   more drastic on its own: disabling or containing an account is left to [threat detection](threat-detection.md)
   playbooks.

This guide covers receiving. Better IAM also sends its own events to other receivers: see the
[Shared Signals transmitter](protocols.md#shared-signals-caep-and-risc).

Reading sources and events needs `iam:signals:read`. Registering and changing sources, reprocessing events, and polling
on demand need `iam:signals:manage`. Both are checked on `iam/signals/sources` and `iam/signals/events`, with `/{id}`
added for a single record, and every change also needs a recent sign-in.

## Supported events

| Event type                           | Spec | What the provider reports                                                                | Receiver                                |
| ------------------------------------ | ---- | ---------------------------------------------------------------------------------------- | --------------------------------------- |
| `session-revoked`                    | CAEP | A session of the person was ended                                                        | records; ends sessions if set           |
| `credential-change`                  | CAEP | A credential was created, changed, revoked or deleted (`credential_type`, `change_type`) | records; ends sessions if set           |
| `token-claims-change`                | CAEP | Claims the provider asserts about the person changed                                     | records; ends sessions if set           |
| `assurance-level-change`             | CAEP | The person's authentication assurance level changed                                      | records; ends sessions if set           |
| `device-compliance-change`           | CAEP | A device of the person became compliant or non-compliant                                 | records; ends sessions if set           |
| `risk-level-change`                  | CAEP | The provider's risk level for the person changed (`current_level`)                       | records; ends sessions if set           |
| `account-disabled`                   | RISC | The account was disabled, for example because it was hijacked                            | records; ends sessions if set           |
| `account-enabled`                    | RISC | The account was enabled again                                                            | records; ends sessions if set           |
| `account-purged`                     | RISC | The account was deleted                                                                  | records; ends sessions if set           |
| `account-credential-change-required` | RISC | The person must change a credential                                                      | records; ends sessions if set           |
| `credential-compromise`              | RISC | A credential of the person was compromised                                               | records; ends sessions if set           |
| `identifier-changed`                 | RISC | An identifier of the account (email, phone number) changed                               | records; ends sessions if set           |
| `identifier-recycled`                | RISC | An identifier now belongs to a different account                                         | records; ends sessions if set           |
| `sessions-revoked`                   | RISC | All sessions of the person were ended (deprecated by RISC in favour of CAEP)             | records; ends sessions if set           |
| `verification`                       | SSF  | The provider is testing the stream                                                       | notes `lastVerifiedAt` on the source    |
| `stream-updated`                     | SSF  | The provider changed the stream's status                                                 | notes a pause or disable as `lastError` |

Event types are recognized by their exact URI (`https://schemas.openid.net/secevent/caep/event-type/session-revoked`
and so on). The two control events are also accepted under the RISC namespace, where Google still sends them, and under
the namespace of the interim SSE drafts. Any other event type is accepted and recorded as `ignored` (reason
`unsupported-event`), for example RISC's OAuth `tokens-revoked`. Control events never touch a person: they only update
the source.

## Registering a source

```ts
const { source, pushUrl, pushToken } = await iam.api.signals.createSource(admin, {
  tenantId,
  name: 'Acme Okta',
  issuer: 'https://acme.okta.com',
  issuerAliases: ['https://acme.okta.com/oauth2/default'],
  audiences: ['https://iam.example.com'],
  delivery: 'push',
  subjects: {
    connectionIds: ['acme-okta'], // the organization's Okta sign-in connection
    scimConnectionIds: ['acme-okta-scim'], // the SCIM connection Okta provisions through
    matchEmail: true,
  },
  actions: { 'session-revoked': 'revoke-sessions', 'credential-compromise': 'revoke-sessions' },
});
// Configure the provider to POST to pushUrl with `Authorization: Bearer ${pushToken}`.
// The token is returned only here; rotatePushToken issues a new one.
```

| Field           | Meaning                                                                                                                                                                                                                                                                |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`          | A label for administrators, at most 128 characters.                                                                                                                                                                                                                    |
| `issuer`        | The `iss` of the provider's SETs: an https URL of at most 512 characters, without credentials, query or fragment. A trailing slash is dropped, and SETs are accepted with or without it. Each organization has one source per issuer (`CONFLICT`).                     |
| `issuerAliases` | Up to 5 other spellings of the issuer. SETs may use them as `iss` and `iss_sub` subjects may name them. They are also tried as the issuer of federation links, for example the issuer of an Okta custom authorization server that the sign-in connection uses.         |
| `audiences`     | 1 to 10 accepted `aud` values of at most 256 characters each. A SET must name at least one of them.                                                                                                                                                                    |
| `jwks`          | Static public keys, 1 to 20 of them: RSA keys of at least 2048 bits, EC keys on P-256, P-384 or P-521, or Ed25519 keys. Only signature keys are accepted, and private key members are refused.                                                                         |
| `jwksUri`       | Where the provider publishes its keys (https, on a public address). Give `jwks` or `jwksUri`, not both. With neither, the keys are found by [discovery](#keys).                                                                                                        |
| `algorithms`    | The signature algorithms accepted, a subset of RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384 and EdDSA. The default is RS256, ES256, PS256 and EdDSA. HMAC algorithms and `none` are never accepted.                                                          |
| `delivery`      | `push` or `poll`. This cannot change after creation.                                                                                                                                                                                                                   |
| `pushToken`     | Push sources only. Generates a bearer token that the provider must send with every push. The default is `true`; pass `false` for providers that cannot send one.                                                                                                       |
| `poll`          | Poll sources only (required for them): `{ endpoint, token, maxEvents? }`. The endpoint is the provider's https poll URL. The token is its bearer token (1 to 4096 printable characters, no spaces), stored sealed. `maxEvents` is 1 to 100 per request, 25 by default. |
| `subjects`      | How subjects map to people: `connectionIds`, `scimConnectionIds` (at most 10 each) and `matchEmail`. See [Matching subjects to people](#matching-subjects-to-people). Nothing is mapped by default, so every event is `unmatched`.                                     |
| `actions`       | Per event type, `record` or `revoke-sessions`. Types that are not listed are recorded only. Any event type except the two control events may end sessions.                                                                                                             |
| `requireTyp`    | Require the `secevent+jwt` token type (the default). Set it to `false` only for legacy RISC providers that send no `typ`.                                                                                                                                              |
| `tenantClaim`   | Accept only SETs whose `tenant_id` claim equals this value (others are refused as `invalid_audience`). Set it for a Better IAM transmitter, which signs every organization's events with one issuer and key; `updateSource` with `null` removes it.                    |

An organization may register at most 20 sources (`LIMIT_EXCEEDED`). Nothing is fetched at registration: URLs are
checked against the [address rules](#deployment) only, and the first event shows whether the keys work. After setup,
ask the provider to send a verification event. `lastVerifiedAt` on the source then shows it arrived, and `lastError`
explains a refusal.

Some transmitters, Better IAM's own included, address their SETs to the push URL unless told otherwise. The push URL
contains the source's id, so it is only known after `createSource` returns. In that case, add the URL to the audiences
with `updateSource`, or configure an explicit audience at the transmitter.

### Managing sources

- `listSources` and `getSource` return sources without their secrets: `hasPushToken` stands in for the push token, and
  the poll token is never shown. They report the source's health: `lastEventAt`, `lastVerifiedAt`, `lastError`, and
  for poll sources `poll.lastPolledAt` and `poll.pendingAcks` (a count). The poll endpoint is visible to anyone with
  `iam:signals:read`, so keep secrets in the poll token, never in the URL.
- `updateSource` changes any field except `issuer` and `delivery`. `jwks: null` or `jwksUri: null` clears the keys,
  which switches the source to discovery. A new poll endpoint needs its token again and starts with an empty
  acknowledgement queue, so a stored token is never sent to an endpoint it was not given for. `status: 'disabled'` stops
  the source: its pushes answer 404 and it is not polled. `actions` replaces the whole map, while `subjects` replaces
  only the members given. Any change drops the source's cached keys.
- `rotatePushToken` returns a new bearer token, shown only once. The old token stops working at once. It also gives a
  token to a push source created without one.
- `deleteSource` removes the source. Its pushes answer 404 from then on, and the events it sent stay until they expire.

## Push delivery

The provider sends each SET in its own request:

```http
POST /api/iam/signals/push/{sourceId} HTTP/1.1
Host: iam.example.com
Content-Type: application/secevent+jwt
Authorization: Bearer {pushToken}

eyJhbGciOiJSUzI1NiIsInR5cCI6InNlY2V2ZW50K2p3dCIsImtpZCI6Ii4uLiJ9.eyJpc3MiOiJodHRwczovL...
```

The push URL is the deployment's `baseURL` origin followed by `{signals.pushPath}/{sourceId}`, where the default
`pushPath` is `{basePath}/signals/push`. `createSource` and the source views return it as `pushUrl`. The request body is
at most 64 KiB and the SET itself at most 16 KiB. The bearer token is required only when the source has one, and it is
compared in constant time.

| Status | `err`                                                                    | Meaning                                                                                                                                                  |
| ------ | ------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 202    | (empty body)                                                             | The event is committed. A SET whose issuer and `jti` were received before also gets 202, and nothing is done again.                                      |
| 400    | `invalid_request`, `invalid_key`, `invalid_issuer` or `invalid_audience` | The SET was refused (see [Verification](#verification)). `description` says why. Sending the same SET again gets the same answer.                        |
| 401    | `authentication_failed`                                                  | The bearer token is missing or wrong (with `WWW-Authenticate: Bearer`).                                                                                  |
| 403    | `access_denied`                                                          | The sender's address is in one of the organization's network blocks.                                                                                     |
| 404    | `invalid_request`                                                        | There is no active push source with that id: it is unknown, deleted, disabled, a poll source, or its organization is suspended.                          |
| 405    | `invalid_request`                                                        | The method was not POST (with `Allow: POST`).                                                                                                            |
| 413    | `invalid_request`                                                        | The body is larger than 64 KiB.                                                                                                                          |
| 415    | `invalid_request`                                                        | The content type is not `application/secevent+jwt`.                                                                                                      |
| 429    | `invalid_request`                                                        | The source sent more than 3000 events within the rate-limit window (`rateLimits.windowMs`, 15 minutes by default). `Retry-After` says when to try again. |
| 503    | `invalid_key` or `invalid_request`                                       | The source's keys could not be obtained (`Retry-After: 30`) or storage was busy (`Retry-After: 1`). The provider should send it again.                   |
| 500    | `invalid_request`                                                        | Processing failed unexpectedly.                                                                                                                          |

Error bodies are `application/json` `{ "err": "...", "description": "..." }` as RFC 8935 defines them, and every response
carries `Cache-Control: no-store`. A 202 comes after the event is stored and its action has run: there is no queue in
between. Refusals are also noted on the source as `lastError`, at most once a minute for the same message, so an
administrator sees why a provider's events are not arriving.

The push endpoint is a protocol mount served by `iam.handler` and `iam.nodeHandler`, and it answers before the API
routes. It therefore needs neither the `X-Better-IAM` header nor an `Origin`. With the default `pushPath` under
`basePath`, the route that already serves the IAM API serves pushes too. If you move `pushPath` elsewhere, route that
path to the IAM handler as well.

## Poll delivery

A poll source pulls its events from the provider's RFC 8936 endpoint. Each run of `iam.signals.poll()` does the
following for every active poll source:

1. It POSTs `{ "maxEvents": 25, "returnImmediately": true, "ack": [...], "setErrs": {...} }` to the endpoint, with
   `Authorization: Bearer {token}`. `setErrs` is sent only when there are errors to report. The request has a
   10-second timeout, redirects are refused, and the response may be at most 1 MiB.
2. It reads `{ "sets": { "{jti}": "{SET}" }, "moreAvailable": true | false }`. Each SET is verified, its `jti` must
   equal its key in `sets`, and it is recorded exactly as a push would be.
3. Events that were committed, including duplicates, are **acknowledged with the next request**, never before they
   are stored. That next request may be the first one of the next run. Refused events are reported in `setErrs` with
   the same error codes as a push refusal. Events that could not be processed yet are neither acknowledged nor
   reported, so the provider delivers them again. This happens when the keys are unavailable or storage is busy.
4. It repeats while the provider answers `moreAvailable: true`, up to five requests per source per run.

The run returns `{ sources, received, acknowledged, errors }`. `received` counts new events, `acknowledged` counts the
acknowledgements the provider accepted, and `errors` counts failed requests and events left for redelivery. A failed
request is noted on the source as `lastError` (for example "The poll endpoint answered 500"), and the pending
acknowledgements are kept for the next attempt. Long polling is not used: `returnImmediately` is always true, so the
job's interval is the delay. `signals.poll({ tenantId, sourceId })` polls one source right away, for example behind a
"Check now" button.

The poll token is sealed with the deployment secret, bound to its source, and re-sealed by `iam.rotateSecrets()`. A
token sealed under a secret that is no longer configured cannot be opened: the source records that as `lastError` until
an administrator gives the token again with `updateSource`.

## Verification

A SET is accepted only if all of the following hold:

- **Shape.** It is a compact JWS of at most 16 KiB. Encrypted SETs (JWE) and unsigned tokens are refused.
- **Keys come from the source, never from the token.** Headers carrying key material or key locations (`jwk`, `jku`,
  `x5u`, `x5c`) are refused, and so is any `crit` header.
- **Algorithm.** The header's `alg` is one of the source's `algorithms`.
- **Type.** `typ` is `secevent+jwt`, compared without regard to case and with or without the `application/` prefix.
  This keeps other tokens signed with the same keys, such as ID tokens and access tokens, from passing as events. A
  source with `requireTyp: false` also accepts no `typ` at all, or `JWT`.
- **Signature.** A key of the source verifies the signature. When several keys could match (a token without a `kid`,
  or keys without one), each candidate is tried, up to 20.
- **Issuer and audience.** `iss` is the source's issuer or one of its aliases, with or without a trailing slash, and
  `aud` (a string or a list of at most 20) names one of the source's audiences.
- **Time.** `iat` is at most five minutes in the future and at most seven days old. There is no shorter age limit,
  because a polled event may wait in the provider's queue. `exp` and `nbf` are honoured when present, with five minutes
  of tolerance.
- **Claims.** `iss`, `aud`, `iat`, `jti` and `events` are present, and `events` holds exactly one event whose value is
  an object, nested at most ten levels deep. A `nonce` claim is refused, since only ID tokens carry one. `iss`, `jti`,
  `txn` and each audience are strings of at most 512 characters.
- **Subject.** The subject, when there is one, is a valid subject identifier (see below). If both a top-level `sub_id`
  and a legacy `events[type].subject` are present, they name the same subject, and a top-level `sub` does not
  contradict an `iss_sub` subject of the same issuer.

Refusals answer `invalid_key` for key, algorithm and signature problems, `invalid_issuer` for the issuer,
`invalid_audience` for the audience, and `invalid_request` for everything else.

**Subject identifiers.** The subject is read from the top-level `sub_id` (RFC 9493) or from the legacy
`events[type].subject`. The accepted formats are:

- `iss_sub`, `email`, `opaque`, `account`, `phone_number`, `did` and `uri`.
- `aliases`, with at most 10 identifiers and no alias list inside another.
- SSF `complex`, with the members `user`, `session`, `device`, `tenant`, `group`, `application` and `org_unit`.
- Legacy RISC subjects, whose `subject_type` is `iss-sub`, `email`, `phone` or `id_token_claims`.

Every string must be 1 to 512 characters without control characters, and nesting may go at most three levels deep. Any
other format is refused. The subject is stored as parsed, up to 8 KiB. The event's own claims are stored up to 4 KiB;
beyond that, the members that fit are kept and `_truncated: true` is added.

**Duplicates.** Within an organization, a SET is identified by its source's issuer and its `jti`. A repeated one is
answered as accepted and acknowledged, and nothing is done again. This also holds when the same event arrives twice at
the same moment.

## Keys

- **Static keys** (`jwks`) are used as given. To roll them, update the source with both the old and the new keys, then
  remove the old ones once the provider has switched.
- **A key URL** (`jwksUri`) is fetched through the guarded transport: https on a public address, no redirects, at most
  256 KiB, a five-second timeout. The key set is cached for ten minutes. A token whose `kid` the cached set lacks
  causes a refetch, at most every 30 seconds.
- **Discovery**, used when a source has neither, reads `{issuer origin}/.well-known/ssf-configuration{issuer path}`
  and then the legacy `/.well-known/risc-configuration{issuer path}`. The document's `issuer` must name the source (its
  issuer or an alias), and its `jwks_uri` is then used under the same rules. A discovered key location is refreshed
  daily. A failed discovery is retried after 30 seconds at the earliest, and a failed refresh keeps the keys found
  before.

A provider whose keys cannot be obtained has not proven anything wrong with its event. That covers a key set that
cannot be fetched, a response other than 200, a body that is not a public key set, a failed discovery, and a token
signed by a new remote key that is not published yet. These refusals are temporary: a push answers 503 and a polled
event stays unacknowledged, so the provider delivers it again. With static keys, an unknown `kid` is a permanent
`invalid_key`.

## Matching subjects to people

| Subject                                                  | Matches                                                                                                                                                                                     | Needs                                  |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| `iss_sub` whose `iss` is the source's issuer or an alias | First, the person linked to that subject by a sign-in through one of `connectionIds`. Then, the person provisioned through one of `scimConnectionIds` whose SCIM `externalId` is the `sub`. | `connectionIds` or `scimConnectionIds` |
| `opaque`                                                 | The person provisioned through one of `scimConnectionIds` whose `externalId` is the `id`.                                                                                                   | `scimConnectionIds`                    |
| `email`, `account` (`acct:user@host`)                    | The person with that email address, when its domain is a verified domain of the organization.                                                                                               | `matchEmail: true`                     |
| `complex`                                                | Its `user` member, matched as above. Session, device, organization, group and application members name no person.                                                                           |                                        |
| `aliases`                                                | Each identifier in turn, until one matches.                                                                                                                                                 |                                        |
| `phone_number`, `did`, `uri`, `iss_sub` of other issuers | Nobody.                                                                                                                                                                                     |                                        |

- **Federation links** are created when a person signs in through an OAuth, OIDC or SAML connection of the
  organization. A link is keyed by the connection, the issuer the connection's tokens name, and the subject. The
  receiver tries the SET's issuer with and without a trailing slash, and every alias of the source. When the sign-in
  connection's issuer differs from the SET issuer (an Okta custom authorization server, or Google's trailing slash),
  add the connection's issuer as an alias. SAML links store the identity provider's entity ID and the NameID, so they
  match only when the provider's `iss_sub` subjects use those same values. Usually they do not, and SCIM or email is the
  better choice.
- **SCIM `externalId`** is the provider's own user ID in most directories, and it is often the same value that the
  provider's `iss_sub` and `opaque` subjects carry.
- **Email** matches only at domains the organization has verified with the `domains` API. Anyone can hold an address at
  a domain the organization does not control, so an unverified domain never matches. Addresses are trimmed and
  lowercased before the lookup.
- **Never matched:** service accounts, AI agents, deleted identities, and anyone in another organization, child
  organizations included.
- **Sessions.** Better IAM does not know a provider's own session IDs, so a `session-revoked` event about one session
  of a person ends all of that person's sessions when the action is `revoke-sessions`.

An event that matches nobody is kept as `unmatched`, with reason `no-match`, or `no-subject` when the SET named none.
After fixing the mapping or the directory, `signals.reprocess({ tenantId, eventId })` maps it again.

## What happens to an event

Each event is handled in one transaction: verified, deduplicated, applied, stored, audited, and noted on the source as
`lastEventAt`. Its status is one of:

| Status      | Meaning                                                                                                                                                                                     |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `applied`   | The source's action for the event type (`revoke-sessions`) ran.                                                                                                                             |
| `recorded`  | The event was kept. It matched a person and the action is `record`, or it was a control event.                                                                                              |
| `unmatched` | No person of the organization matched its subject (`no-match`, `no-subject`).                                                                                                               |
| `ignored`   | The event type is not supported (`unsupported-event`), or the action was refused for a protected person (`protected`).                                                                      |
| `failed`    | Applying it failed. The reason is the error code. It is stored in a transaction of its own and acknowledged, so the provider does not send it again, and an administrator can reprocess it. |

**Actions.** `record`, the default, keeps the event and does nothing else. `revoke-sessions` ends every session of the
person except API keys. That covers sign-in sessions, role sessions and session tokens (with impersonation sessions
opened through them), role sessions the person assumed in other organizations, and pending sign-in challenges.
Remembered devices stay, so the next sign-in works as usual, and so do API keys. The revocation is audited as
`signal:revoke-sessions` with the number of sessions ended. If you run the OAuth provider, its `logoutEndedSessions()`
sweep then signs the person out of the connected applications too.

**Root administrators are protected.** A source of any organization except the root organization never ends a root
administrator's sessions. The event is `ignored` with reason `protected`.

**Reprocessing.** `signals.reprocess` handles an `unmatched` or `failed` event of an active source again, as if it had
just arrived: it maps the subject and runs the configured action. An event that now matches someone is audited as
`signal:received` again, so threat detection sees it, and the call itself is audited as `signal:reprocess`.

## Threat detection and containment

The receiver never disables or contains an account by itself: what an upstream "disabled" or "compromised" should mean
differs between organizations. Instead, every received event is audited as `signal:received`:

- actor `signal:{sourceId}`;
- resource the matched identity, or `signals/sources/{sourceId}` when nobody matched;
- metadata `{ sourceId, eventType, jti, status, identityId?, reasonAdmin?, currentLevel?, credentialType? }`, where
  `reasonAdmin` is CAEP `reason_admin` (English, or else the first language given, at most 256 characters),
  `currentLevel` is the upper-cased `current_level` of a `risk-level-change`, and `credentialType` is the event's
  `credential_type`.

Threat detection's `upstream-signal` rule turns matched events into detections about the person:

| Event                                                                      | Detection |
| -------------------------------------------------------------------------- | --------- |
| `credential-compromise`                                                    | high      |
| `risk-level-change` to `HIGH`                                              | high      |
| `risk-level-change` to `MEDIUM`                                            | medium    |
| `account-disabled`, `account-purged`, `account-credential-change-required` | medium    |
| `credential-change`                                                        | low       |
| `session-revoked`, `risk-level-change` to `LOW`, and the rest              | none      |

A detection raises the person's risk, which policies read as `principal.riskLevel`. It also opens an incident and runs
the organization's playbooks, and that is where containment belongs:

```ts
await iam.api.threats.createPlaybook(admin, {
  tenantId,
  name: 'Contain people our identity provider reports compromised',
  trigger: { ruleIds: ['upstream-signal'], minSeverity: 'high' },
  actions: [{ kind: 'contain' }, { kind: 'notify' }],
});
```

The playbook protections apply: owners and root administrators are never contained automatically, and the brake limits
how many people one run contains. To forward received events to a SIEM, subscribe a webhook to `signal:*`.

## Avoiding echo loops

A provider can be both a transmitter and a receiver. Okta is one example, and another Better IAM deployment is another.
If the receiver's actions were audited under the names the transmitter publishes, a revocation received from a
provider would be sent straight back to it. The receiver therefore records everything under its own `signal:*` names.
The transmitter maps none of them, so nothing the receiver does is transmitted: `signal:revoke-sessions` is not
`identity:revoke-sessions`. The trade-off is that receivers of your own streams are not told about sessions that ended
because of an upstream signal.

Threat detection responses are different: the transmitter sends `threat:revoke-sessions` as CAEP `session-revoked` and
`threat:contain` as RISC `account-disabled`. A playbook that contains someone because of a provider's signal therefore
tells every stream of the organization, including the provider's own stream if it is one. If that provider should not
hear back about containments it caused, leave those event types out of its stream's `events`.

## Setting up providers

For every provider, find out and configure:

1. **Issuer.** The provider's SET `iss`, and whether its sign-in tokens use a different issuer (add that as an alias).
2. **Keys.** Whether discovery works on the issuer. If it does not, set `jwksUri` or static `jwks`.
3. **Audience.** The `aud` the provider puts in its SETs.
4. **Delivery.** For push, give the provider the push URL and, if it can send one, the bearer token. For poll, set the
   provider's endpoint and token.
5. **Subjects.** The subject format the provider uses, and which mapping reaches your people: federation links, SCIM,
   or email.
6. **Events.** Which event types the provider sends, and which of them should end sessions.

Then have the provider send a verification event and check `lastVerifiedAt` and `lastError` on the source.

The vendor details below are starting points. Provider offerings change, so **confirm each one against the vendor's
current documentation** before relying on it.

### Another Better IAM deployment

Better IAM's own [transmitter](protocols.md#shared-signals-caep-and-risc) needs no guesswork:

```ts
// Downstream deployment: register the upstream transmitter.
const { source, pushUrl, pushToken } = await downstream.api.signals.createSource(admin, {
  tenantId,
  name: 'Acme identity',
  issuer: 'https://id.acme.example/oidc', // the transmitter's `issuer`
  jwksUri: 'https://id.acme.example/oidc/jwks', // or leave it out when upstream mounts `signals.handler`
  audiences: ['https://iam.example.com/signals/acme'],
  delivery: 'push',
  subjects: { connectionIds: ['acme-oidc'] },
  actions: { 'session-revoked': 'revoke-sessions' },
  // Every organization upstream shares the transmitter's issuer and key: accept only this one's events.
  tenantClaim: '<upstream organization id>',
});

// Upstream deployment (`signals` is its createSharedSignalsTransmitter instance): stream the organization's events.
const stream = await signals.createStream(upstreamAdmin, {
  tenantId: upstreamTenantId,
  name: 'Example IAM',
  endpointUrl: pushUrl!,
  audience: 'https://iam.example.com/signals/acme',
  authorization: `Bearer ${pushToken}`,
});
await signals.verifyStream(upstreamAdmin, { tenantId: upstreamTenantId, streamId: stream.id });
```

The transmitter sends `iss_sub` subjects whose `sub` is the upstream identity ID. These match federation links when
the organization signs in through an OIDC connection to the upstream deployment's OAuth provider, whose issuer the
transmitter usually shares. Otherwise, create the stream with `subjectFormat: 'email'` and turn on `matchEmail`.

### Okta

To be confirmed against Okta's documentation: which Okta plans transmit SSF events, which event types they include,
how streams are created (Okta's SSF stream configuration API), and the `aud` and subject format Okta sends.

- **Issuer:** the Okta org URL, such as `https://acme.okta.com`. If the organization's sign-in connection uses a custom
  authorization server (`https://acme.okta.com/oauth2/default`), add that issuer as an alias so federation links
  match.
- **Keys:** discovery on the issuer (`/.well-known/ssf-configuration`), or the `jwks_uri` its document names.
- **Delivery:** push. Give Okta the push URL and the bearer token as the stream's authorization header.
- **Subjects:** `iss_sub` subjects carry the Okta user ID (`00u…`), which is also the `sub` of Okta ID tokens and the
  SCIM `externalId` Okta provisions. List the Okta sign-in connection in `connectionIds` and the Okta SCIM connection
  in `scimConnectionIds`. Turn on `matchEmail` for email subjects.
- **Actions:** `session-revoked` → `revoke-sessions` is the usual choice.

### Microsoft Entra ID

To be confirmed against Microsoft's documentation: whether and how Microsoft Entra ID transmits Shared Signals to
third-party receivers, the issuer and keys of its SETs, and the subject format it sends.

- **Subjects:** Entra ID tokens carry a `sub` that differs per application, so federation links rarely match an Entra
  subject. Map people through SCIM instead: if the signals name the user's object ID, map `objectId` to `externalId`
  in the Entra provisioning attribute mappings and list the SCIM connection in `scimConnectionIds`. Alternatively, map
  by email with `matchEmail` on the organization's verified domains.
- **Issuer:** Entra issuers are specific to the Entra tenant (`https://login.microsoftonline.com/{tenant-id}/v2.0` for
  its tokens). Use exactly the `iss` its SETs carry.

### Google (RISC, Cross-Account Protection)

To be confirmed against Google's documentation: how the receiver is registered with the RISC API, the event types
Google sends, and its headers.

- **Issuer:** `https://accounts.google.com/`, stored without the trailing slash. Both spellings are accepted.
- **Keys:** discovery finds `https://accounts.google.com/.well-known/risc-configuration` and its `jwks_uri`, so leave
  `jwks` and `jwksUri` out.
- **Audience:** the OAuth client IDs of the Google Cloud project that people sign in with.
- **Type and subject:** Google's SETs carry no `typ` and put the subject inside the event (`subject_type: iss-sub`),
  so set `requireTyp: false`. The `sub` is the Google account ID, the same as in Google ID tokens, so list the Google
  sign-in connection in `connectionIds`.
- **Delivery:** push, with `pushToken: false` if Google does not send a bearer token. The signature authenticates each
  event either way.
- **Events:** `sessions-revoked` → `revoke-sessions` ends sessions after Google detects a hijacking. RISC's OAuth token
  events are recorded as `ignored`.

Google registers one receiver per Google Cloud project, while a source belongs to one organization. A project whose
OAuth clients serve many organizations can therefore route its events to only one of them.

### Providers without Shared Signals

If a provider offers only webhooks or an API, a small service you run can turn its notifications into SETs signed with
the service's own key. Register the service as a source with static `jwks`, and have it push to the source's URL or hand
the SETs in with `iam.signals.receive`.

## Deployment

```ts
const iam = betterIam({
  // ...
  signals: {
    pushPath: '/api/iam/signals/push', // the default: `${basePath}/signals/push`
    allowPrivateNetworks: false,
    allowInsecureLocalhost: false,
  },
});
```

| Option                           | Meaning                                                                                                                                                                                                                                             |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `signals.pushPath`               | Where providers push: `{pushPath}/{sourceId}`. An absolute path of letters, digits, `_`, `-` and `/` (at most 256 characters, no trailing slash), `{basePath}/signals/push` by default.                                                             |
| `signals.allowPrivateNetworks`   | Lets key, discovery and poll requests reach private and reserved addresses. Organization administrators choose these URLs, so this lets them make the server call into your network. Enable it only for providers on your own network, or in tests. |
| `signals.allowInsecureLocalhost` | Accepts `http://` issuers, key URLs and poll endpoints on loopback hosts. For development and tests only.                                                                                                                                           |

Every outbound request, whether for keys, discovery documents or polls, goes through the guarded transport. It checks
the address at connect time (which defeats DNS rebinding), refuses redirects, and bounds the response size and time.

**The poll job.** Run `iam.signals.poll()` every minute or so beside your other jobs. It needs no credential, and what
it records is audited by the actor `signal:{sourceId}`. It is harmless to overlap: an event delivered twice is
recognized as a duplicate and acknowledged again.

```ts
setInterval(() => void iam.signals.poll().catch(reportError), 60_000).unref();
```

`iam.signals.poll({ sourceId })` polls one source. Deployments without poll sources can skip the job: pushes need
nothing scheduled.

**Custom transports.** `iam.signals.receive(sourceId, set)` verifies and records one SET for an active source exactly as
a push does, for example from a queue consumer. It returns `{ eventId, status, duplicate, identityId? }`. It throws
`SignalRejectedError` (code `SIGNAL_REJECTED`, with the RFC 8935 `err` and `temporary: true` when a later attempt may
pass), or `NOT_FOUND` for an unknown or disabled source.

**Storage and retention.** Sources live in `signalSources` and received events in `signalEvents`. Both belong to the
organization and are deleted with it. Events expire 90 days after receipt and are removed by `iam.sweepExpired()`; the
audit trail keeps their `signal:received` events. Push tokens are stored as SHA-256 hashes. Poll tokens are sealed and
re-sealed by `iam.rotateSecrets()`.

**Transport and regions.** The Node transport reads at most 64 KiB under `basePath`, and the push endpoint caps its
own body at 64 KiB on every transport. The push URL uses the deployment's `baseURL`. In a multi-region deployment, give
providers the push URL of the organization's home region: transmitters, Better IAM's included, do not follow redirects.

## Audit events

The `signals` group records its operation events (`iam:signals:read`, `iam:signals:manage`). The receiver also records
`signal:received`, `signal:revoke-sessions`, `signal:source-create`, `signal:source-update`, `signal:source-delete`,
`signal:source-rotate` and `signal:reprocess`, subscribable as `signal:*`. Their metadata is listed in
[events](events.md#shared-signals-receiver-events). Events about received SETs are recorded by the actor
`signal:{sourceId}`, and changes to sources by the administrator who made them.

## Limits

| Limit                                  | Value                                               |
| -------------------------------------- | --------------------------------------------------- |
| Sources per organization               | 20                                                  |
| Issuer aliases, audiences, static keys | 5, 10, 20                                           |
| Connection ids per mapping list        | 10                                                  |
| Push request body / SET                | 64 KiB / 16 KiB                                     |
| Pushes per source                      | 3000 per rate-limit window (`rateLimits.windowMs`)  |
| Poll requests per source and run       | 5, each with `maxEvents` (1 to 100, 25 by default)  |
| Poll response                          | 1 MiB, 10 seconds                                   |
| Key set / discovery document           | 256 KiB / 64 KiB, 5 seconds each                    |
| SET age                                | at most 7 days old, at most 5 minutes in the future |
| Stored event claims / subject          | 4 KiB / 8 KiB                                       |
| Received event retention               | 90 days                                             |

## Not offered

- **Stream management as a receiver.** The receiver does not use a provider's SSF stream configuration, status,
  verification or subject endpoints. Streams are set up at the provider by an administrator, and verification events
  are requested there.
- **Encrypted SETs** (JWE).
- **Long polling.** Polls always ask the provider to return immediately.
- **Matching upstream sessions.** Session-level events end all of the person's sessions.
- **Deployment-wide sources.** Each source belongs to one organization and matches only that organization's people.
