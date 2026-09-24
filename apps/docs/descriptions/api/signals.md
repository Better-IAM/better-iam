# signals

The Shared Signals receiver: security events that an organization's identity providers send about its people. An
upstream provider (Okta, Google, another Better IAM deployment) reports that a credential was compromised, a session
ended, a risk level changed, or an account was disabled. It does so as signed Security Event Tokens (SETs, RFC 8417)
with OpenID SSF 1.0, CAEP, and RISC event types. Each organization registers its providers here as **sources**. Events
arrive by push or poll, are verified and matched to a person of the organization, and are recorded with a status. They
are audited as `signal:received` for threat detection, and they end the person's sessions where a source asks for it.
Sending events the other way is the [transmitter](/docs/federation/shared-signals). The repository guide is
`docs/shared-signals-receiver.md`.

## How events arrive

- **Push (RFC 8935).** A push source gets a push URL, `{signals.pushPath}/{sourceId}` on the deployment's origin
  (`/api/iam/signals/push/{sourceId}` by default). By default it also gets a bearer token, returned once by
  [`createSource`](#createsource). The provider POSTs each SET there as `application/secevent+jwt`. The endpoint answers
  `202` with an empty body once the event is stored and its action has run, including for a SET received before. A
  refused SET gets `400` with `{ "err", "description" }` (`invalid_request`, `invalid_key`, `invalid_issuer`,
  `invalid_audience`). Other answers are `401` for a bad bearer token, `404` for an unknown, disabled, or poll source,
  `413` over 64 KiB, `415` for another content type, `429` past 3000 events per rate-limit window, and `503` while the
  source's keys cannot be fetched. The endpoint is a protocol mount: it needs no `X-Better-IAM` header and is not one of
  this group's methods.
- **Poll (RFC 8936).** A poll source stores the provider's poll endpoint and bearer token (sealed). The scheduler job
  [`iam.signals.poll()`](/docs/reference/api#shared-signals-receiver) posts
  `{ maxEvents, returnImmediately: true, ack, setErrs }`. It records the SETs it gets back and acknowledges each one
  with the next request, only after it is stored. It follows `moreAvailable` for up to five requests per source and run.
  [`poll`](#poll) runs it for one source now.
- **In process.** `iam.signals.receive(sourceId, set)` hands in one SET from a custom transport, exactly as a push.

## Verification

A SET is at most 16 KiB and in compact JWS form. It carries no `jwk`, `jku`, `x5u`, `x5c`, or `crit` header, and it is
signed with one of the source's `algorithms` by one of its keys: static `jwks`, a `jwksUri`, or SSF discovery on the
issuer. Its `typ` is `secevent+jwt`, unless the source sets `requireTyp: false` for legacy RISC providers such as
Google. `iss` is the source's issuer or an alias, and `aud` names one of its audiences. `iat` is at most seven days old
and at most five minutes in the future. `events` holds exactly one event, there is no `nonce`, and the subject (`sub_id`
or the legacy `events[type].subject`) is a valid subject identifier. A repeated issuer and `jti` is answered as
accepted and not processed again. Keys that cannot be fetched are a temporary refusal: pushes get `503` and polled
events stay unacknowledged, so the provider sends them again.

## Matching and actions

Subjects map only to people of the source's organization, never to service accounts, agents, or deleted identities:

- `iss_sub` of the source's issuer or an alias matches through the federation links of `subjects.connectionIds`, then
  through the SCIM `externalId` of users provisioned by `subjects.scimConnectionIds`;
- `opaque` matches through the SCIM `externalId`;
- `email` and `acct:` subjects match by email, with `subjects.matchEmail`, only at domains the organization verified
  (see [`domains`](/docs/reference/api/domains));
- `complex` subjects match through their `user` member, and `aliases` through each identifier in turn.

Each received event has a status: `applied`, `recorded`, `unmatched`, `ignored`, or `failed`. A source's `actions` map
an event type to `record` (the default) or `revoke-sessions`, which ends every session of the matched person except API
keys and is audited as `signal:revoke-sessions`. Root administrators are protected: only a source of the root
organization ends their sessions, and otherwise the event is `ignored` with reason `protected`. Nothing else happens
automatically. The `signal:received` audit event (metadata `sourceId`, `eventType`, `jti`, `status`, `identityId`,
`reasonAdmin`, `currentLevel`, `credentialType`) feeds threat detection, where playbooks decide on containment (see
[`threats.createPlaybook`](/docs/reference/api/threats#createplaybook)). The receiver's actions use their own `signal:*`
names, which the transmitter never publishes, so a revocation received from a provider is not sent back to it.

## Who may call what

Reading needs `iam:signals:read`, and everything else `iam:signals:manage`. They are checked on `iam/signals/sources`
and `iam/signals/events`, with `/{id}` for one record. Changes also need a recent sign-in (`RECENT_AUTH_REQUIRED`).
Every call is audited under its permission, reads included, and changes also record the `signal:*` event each method
names. Views never contain the push token hash or the poll token.

## createSource

Registers an identity provider as a signal source for the organization.

- **Permission:** `iam:signals:manage` on `iam/signals/sources`, and a recent sign-in.
- **Audited as:** `iam:signals:manage` and `signal:source-create` (metadata: `name`, `issuer`, `delivery`).
- **Errors:** `INVALID_INPUT` for a missing or over-long `name`, an issuer that is not https (loopback http only with
  `signals.allowInsecureLocalhost`) or carries credentials, a query, or a fragment, more than 5 `issuerAliases`, not 1
  to 10 `audiences`, both `jwks` and `jwksUri`, keys that are not 1 to 20 public signature keys (RSA of at least 2048
  bits, EC P-256, P-384 or P-521, Ed25519), an unknown algorithm, a `delivery` other than `push` or `poll`, a
  `jwksUri` or poll endpoint that is not https or points at a private address, a poll source without `poll.endpoint`
  and `poll.token` (or a push source with `poll`), a poll token that is not 1 to 4096 printable characters without
  spaces, `maxEvents` outside 1 to 100, more than 10 ids in a mapping list, or an unknown event type or action;
  `CONFLICT` (409) when the organization already has a source for the issuer; `LIMIT_EXCEEDED` (409) past 20 sources;
  `RECENT_AUTH_REQUIRED`.

The result is `{ source, pushUrl?, pushToken? }`. A push source gets its `pushUrl`, plus a bearer token unless
`pushToken: false`. The token is shown only here and stored as a SHA-256 hash; give it to the provider as the stream's
authorization header. Trailing slashes are dropped from issuers, and SETs are accepted with or without them.
`algorithms` defaults to RS256, ES256, PS256, and EdDSA, `requireTyp` to true, `poll.maxEvents` to 25, and `subjects`
to no mapping, which leaves every event `unmatched`. Nothing is fetched now: the first event shows whether the keys
work. Ask the provider for a verification event and check `lastVerifiedAt` and `lastError` with
[`getSource`](#getsource).

`tenantClaim` accepts only SETs whose `tenant_id` claim equals it; set it for another Better IAM deployment, whose
transmitter signs every organization's events with one issuer and key.

```ts
const { source, pushUrl, pushToken } = await iam.api.signals.createSource(credential, {
  tenantId,
  name: 'Acme Okta',
  issuer: 'https://acme.okta.com',
  audiences: ['https://iam.example.com'],
  delivery: 'push',
  subjects: { connectionIds: ['acme-okta'], matchEmail: true },
  actions: { 'session-revoked': 'revoke-sessions' },
});
```

## deleteSource

Deletes a signal source; the events it sent stay until they expire.

- **Permission:** `iam:signals:manage` on `iam/signals/sources/{id}`, and a recent sign-in.
- **Audited as:** `iam:signals:manage` and `signal:source-delete` (metadata: `name`, `issuer`).
- **Errors:** `NOT_FOUND` when the source is not in this organization; `RECENT_AUTH_REQUIRED`.

From then on, its pushes answer `404` and it is no longer polled. Received events keep their `sourceId` and are removed
90 days after receipt, and events of a deleted source can no longer be reprocessed. To stop a source for a while, set
`status: 'disabled'` with [`updateSource`](#updatesource) instead.

## getEvent

Returns one received security event.

- **Permission:** `iam:signals:read` on `iam/signals/events/{id}`.
- **Audited as:** `iam:signals:read`.
- **Errors:** `NOT_FOUND` when the event is not in this organization.

An event names its `sourceId`, `jti`, `eventType` and `eventUri`, the SET's `issuedAt` and, when the SET carried them,
`eventTimestamp` (both in epoch milliseconds) and `txn`. It keeps the parsed `subject`, the matched
`identityId`, its `status` with a `reason` (`no-match`, `no-subject`, `unsupported-event`, `protected`, or an error
code for `failed`), the event's own `claims` (up to 4 KiB, else `_truncated: true`), `receivedAt`, `expiresAt`, and
`reprocessedAt`/`reprocessedBy` once reprocessed. The signed token itself is not kept.

## getSource

Returns one signal source with its health.

- **Permission:** `iam:signals:read` on `iam/signals/sources/{id}`.
- **Audited as:** `iam:signals:read`.
- **Errors:** `NOT_FOUND` when the source is not in this organization.

Besides its settings, a source reports `pushUrl` and `hasPushToken` for push delivery, or `poll` (`endpoint`,
`maxEvents`, `pendingAcks` as a count, `lastPolledAt`) for poll delivery. It also reports `lastEventAt`,
`lastVerifiedAt` (the provider's last verification event), and `lastError`: the last refused event, failed poll, or
stream the provider paused or disabled, with its time. The poll endpoint is visible to readers, so keep secrets in the
poll token rather than the URL.

## listEvents

Lists received events, newest first, optionally narrowed by source, status, identity, and event type.

- **Permission:** `iam:signals:read` on `iam/signals/events`.
- **Audited as:** `iam:signals:read`.
- **Errors:** `INVALID_INPUT` for an unknown `status` or `eventType`, a `limit` outside 1 to 1000, or an `offset`
  outside 0 to 1,000,000.

`status` is `applied`, `recorded`, `unmatched`, `ignored`, or `failed`. `eventType` is a known type such as
`session-revoked`, or `unknown` for unsupported ones. The result is `{ events, total }`; page with `limit` (100 by
default) and `offset`. Filter on `status: 'unmatched'` to find events whose subject mapping needs attention.

## listSources

Lists the organization's signal sources, oldest first.

- **Permission:** `iam:signals:read` on `iam/signals/sources`.
- **Audited as:** `iam:signals:read`.

Each source has the same shape as [`getSource`](#getsource) returns.

## poll

Polls one poll source now, as the scheduled `iam.signals.poll()` does, and returns what it did.

- **Permission:** `iam:signals:manage` on `iam/signals/sources/{id}`.
- **Audited as:** `iam:signals:manage`, plus whatever the received events record (`signal:received`,
  `signal:revoke-sessions`) by `signal:{sourceId}`.
- **Errors:** `INVALID_INPUT` for a push source; `INVALID_TRANSITION` (409) for a disabled source; `NOT_FOUND` when the
  source is not in this organization.

The permission and the source are checked first, and then the provider is called outside any transaction. The result
is `{ sources, received, acknowledged, errors }`. A failed request is reported in `errors` and recorded on the source
as `lastError` rather than thrown. Use it behind a "Check now" button or after fixing a source's settings.

## reprocess

Maps an unmatched or failed event again and runs the source's action for it, after the mapping or the directory changed.

- **Permission:** `iam:signals:manage` on `iam/signals/events/{id}`, and a recent sign-in.
- **Audited as:** `iam:signals:manage` and `signal:reprocess` (metadata: `sourceId`, `eventType`, `jti`,
  `previousStatus`, `status`, `identityId`). If the event now matches someone, it is also audited as `signal:received`
  again, and as `signal:revoke-sessions` when the action ran.
- **Errors:** `INVALID_TRANSITION` (409) for an event that is neither `unmatched` nor `failed`, or whose source is
  disabled; `NOT_FOUND` for the event, or when its source was deleted; `RECENT_AUTH_REQUIRED`.

The event is handled with the source's current `subjects` and `actions`, as if it had just arrived. The result is the
updated event with `reprocessedAt` and `reprocessedBy`. Because the new `signal:received` reaches threat detection,
link the person first (a sign-in through the connection, SCIM provisioning, or a verified domain), then reprocess.

## rotatePushToken

Replaces a push source's bearer token and returns the new one, shown only once.

- **Permission:** `iam:signals:manage` on `iam/signals/sources/{id}`, and a recent sign-in.
- **Audited as:** `iam:signals:manage` and `signal:source-rotate` (metadata: `replaced`).
- **Errors:** `INVALID_INPUT` for a poll source; `NOT_FOUND`; `RECENT_AUTH_REQUIRED`.

The old token stops working at once, so update the provider's stream right after. A push source created with
`pushToken: false` gets its first token this way (`replaced: false`), and from then on every push must carry it.

## updateSource

Changes a signal source: names, aliases, audiences, keys, algorithms, poll settings, mapping, actions, type check, or status.

- **Permission:** `iam:signals:manage` on `iam/signals/sources/{id}`, and a recent sign-in.
- **Audited as:** `iam:signals:manage` and `signal:source-update` (metadata: `changed`, the field names).
- **Errors:** `INVALID_INPUT` for an `issuer`, `delivery`, or `pushToken` field, an update that changes nothing, poll
  settings on a push source, a new poll endpoint without its token, and anything [`createSource`](#createsource)
  refuses; `NOT_FOUND`; `RECENT_AUTH_REQUIRED`.

Fields left out keep their values. `jwks: null` or `jwksUri: null` clears the keys; without either, the keys are found
by SSF discovery on the issuer. `subjects` replaces only the members given, and `actions` the whole map. A new
`poll.endpoint` needs `poll.token` again, so a stored token never goes to an endpoint it was not given for, and it starts
with no pending acknowledgements. `status: 'disabled'` makes pushes answer `404` and stops polling until it is set back
to `active`. The issuer and the delivery method never change: register a new source instead. Cached keys are dropped,
so new keys apply to the next event.

```ts
// Accept events addressed to the push URL, and end sessions on credential compromise too.
await iam.api.signals.updateSource(credential, {
  tenantId,
  sourceId,
  audiences: ['https://iam.example.com', pushUrl],
  actions: { 'session-revoked': 'revoke-sessions', 'credential-compromise': 'revoke-sessions' },
});
```
