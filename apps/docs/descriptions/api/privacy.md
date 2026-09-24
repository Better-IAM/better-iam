# privacy

Privacy and consent management for GDPR, UK GDPR, CCPA/CPRA, LGPD and PIPEDA: the purposes a tenant processes personal
data for, each person's consent with a signed receipt and an append-only history, data-subject requests with statutory
deadlines, legal holds that stop erasure, and restriction of processing. People make their own choices from their
session, applications record consent for their own customers, and policies read the result as `principal.consents`.
See the [privacy guide](/docs/guides/governance/privacy); the repository guide is `docs/privacy.md`.

## Subjects

Methods that take a `subject` accept either `identityId` (a person of the tenant; service accounts and agents are not
data subjects, so they answer `INVALID_INPUT`) or `externalId` (1 to 256 visible characters the application chooses,
such as a customer number or a visitor ID), never both. Records name them `identity:ID` and `external:ID`. A request
from someone known only by an email address gets an `email:` subject, a hash of the address keyed with the deployment
secret, until a handler links it with [`linkRequest`](#linkrequest).

## Purposes and consent states

A purpose has a permanent `key`, a `legalBasis` and, for consent, a `mode`. Only consent (`opt-in` or `opt-out`) and
`legitimate-interests` purposes are decided by the person; `contract`, `legal-obligation`, `vital-interests` and
`public-task` purposes are allowed without a record. [`check`](#check) and the other readers answer `allowed` with a
`reason`: `CONSENT_GIVEN`, `NOT_OPTED_OUT`, `LEGITIMATE_INTERESTS` or `LEGAL_BASIS` when processing may go ahead, and
`NO_CONSENT`, `CONSENT_WITHDRAWN`, `CONSENT_EXPIRED`, `CONSENT_OUTDATED`, `OBJECTED`, `RESTRICTED`, `ERASED` or
`PURPOSE_ARCHIVED` when it may not. Publishing a new version (`updatePurpose` with `newVersion: true`) makes opt-in
grants for older versions outdated unless the purpose sets `reconsentOnVersion: false`, and `consentLifetimeDays` makes
grants lapse. Restriction and an erased application subject hold back everything except `legal-obligation` and
`vital-interests` purposes.

## Requests and deadlines

A data-subject request has a `type` (`access`, `portability`, `erasure`, `rectification`, `restriction`, `objection`,
`opt-out`), a `regulation` and a `status`: `pending-verification` until someone confirms who is asking, `open` with a
`dueAt` once verified, then `completed`, `rejected` or `cancelled`. The response window starts at verification: GDPR
and UK GDPR 30 days (extendable once by 60), CCPA 45 (plus 45), LGPD 15 (no extension), PIPEDA and `other` 30 (plus
30); the tenant's `responseDays` setting can only shorten it. `iam.privacy.sendDeadlineReminders()` reminds handlers
of requests due soon and overdue, and lapses public requests nobody confirmed within seven days.

## Permissions

`iam:privacy:manage` covers purposes, legal holds and settings; `iam:privacy:read` consents, history, requests,
holds, restrictions, settings and the summary; `iam:privacy:record` recording consent; `iam:privacy:check` checking
it; and `iam:privacy:handle` handling requests. Actions are checked on `iam/TENANT_ID`, or on the purpose, request or
hold a call acts on (`iam/ID`). Fulfilling access and portability requests, downloading someone else's export and
linking a request to an account also need `iam:identities:read` on the account, and erasure `iam:identities:delete`.
People manage their own choices and requests from their own signed-in session of the organization without any
permission: role sessions, API keys, session tokens and agents acting for them are refused with `ACCESS_DENIED`, and
impersonation with `IMPERSONATION_RESTRICTED`. `submitPublic` and `confirmPublic` need no credential.

## addNote

Adds an internal note to a request's timeline.

- **Permission:** `iam:privacy:handle` on the request.
- **Audited as:** `iam:privacy:handle`.
- **Errors:** `CONFLICT` (409) when erasure redacted the request; `NOT_FOUND` when the request is not in this tenant;
  `INVALID_INPUT` for an empty note or one over 2000 characters.

Notes are never shown to the subject: their own view of the request (`mine`) leaves notes and assignments out. The
timeline keeps the newest 100 events.

## assignRequest

Hands a request to a handler, or clears the assignment with `assigneeId: null`.

- **Permission:** `iam:privacy:handle` on the request.
- **Audited as:** `iam:privacy:handle`.
- **Errors:** `INVALID_TRANSITION` (409) when the request is closed; `INVALID_INPUT` when the assignee is not an active
  person of the tenant; `NOT_FOUND` when the request or the assignee is not in this tenant.

The assignee receives the request's deadline reminders instead of the privacy contact.

## audience

Lists the subjects a purpose may be processed for right now.

- **Permission:** `iam:privacy:read` on the tenant.
- **Audited as:** `iam:privacy:read`.
- **Errors:** `NOT_FOUND` for an unknown purpose; `INVALID_INPUT` for a `limit` outside 1 to 1000.

The list holds every active person of the tenant for whom the purpose is allowed (everyone not opted out or objected
for opt-out and legitimate-interest purposes, those with a live grant for opt-in ones), then every application subject
with a decision that allows it. The result is `total` and a page of `subjects` (`limit` 1000 by default, `offset`).
People carry `email` and `name` only when the caller may also read identities (`iam:identities:read` on the tenant);
otherwise they are listed by `identityId`. Use [`filterSubjects`](#filtersubjects) to check a list you already have.

## cancelMyRequest

Withdraws one of your own requests while it is still being handled.

- **Permission:** None beyond a person's own session of the tenant.
- **Audited as:** `privacy:request:cancel`.
- **Errors:** `NOT_FOUND` when the request is not yours; `INVALID_TRANSITION` (409) when it is already closed.

## check

Tells whether a purpose may be processed for one subject right now, and why.

- **Permission:** `iam:privacy:check` on the tenant.
- **Audited as:** `iam:privacy:check`.
- **Errors:** `NOT_FOUND` for an unknown purpose or identity (including a deleted one); `INVALID_INPUT` for a malformed
  subject or an identity that is not a person.

The result is `purposeKey`, the purpose's current `purposeVersion`, `allowed`, `reason` and, when a decision is
recorded, `consent` (granted, version, time, expiry and receipt id). Server code calls `iam.privacy.check` with the
same input and no credential, not audited.

```ts
const { allowed, reason } = await iam.api.privacy.check(apiKey, {
  tenantId,
  subject: { externalId: 'cus_100' },
  purposeKey: 'marketing-email',
});
```

## confirmPublic

Confirms a public request from the link emailed to the requester.

- **Permission:** None: public, tenant-bound (on an organization's own address `tenantId` may be left out).
- **Audited as:** `privacy:request:verify` (method `email-link`, and whether it was `linked` to an account), or
  `privacy:request:email-confirmed` for a request naming an `externalId`; actor `public-intake`.
- **Errors:** `CONFIRMATION_INVALID` (400) for a wrong, used or expired token, an unknown request, or one that is no
  longer waiting; `RATE_LIMITED` (429) after 10 attempts per request in a rate-limit window.

The confirmation opens the request and starts its deadline. When the address belongs to a person of the tenant with a
verified email, the request is linked to their account. A request naming an `externalId` stays
`pending-verification`, because owning an address does not prove owning the identifier: the call records
`emailConfirmedAt`, emails the privacy contact, and a handler checks the identifier with
[`verifyRequest`](#verifyrequest). The result is `number`, `status` and, once open, `dueAt`. Tokens are single use and
lapse after seven days.

```ts
await client.privacy.confirmPublic({ tenantId, requestId, token });
```

## createPurpose

Adds a processing purpose at version 1.

- **Permission:** `iam:privacy:manage` on the tenant.
- **Audited as:** `iam:privacy:manage`.
- **Errors:** `CONFLICT` (409) when a purpose with the key exists; `LIMIT_EXCEEDED` (409) past 200 purposes;
  `INVALID_INPUT` for a malformed key, a name over 120 characters, an empty description or one over 5000, `opt-out`
  on a basis other than `consent`, `consentLifetimeDays` on a basis other than `consent`, a `retentionDays` outside 1
  to 36500 or a `consentLifetimeDays` outside 1 to 3650, or more than 32 `dataCategories`.

Keys are permanent: 1 to 64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter. `mode`
defaults to `opt-in` and `reconsentOnVersion` to true. `dataCategories` are lowercase identifiers such as `contact` or
`usage`.

```ts
await iam.api.privacy.createPurpose(admin, {
  tenantId,
  key: 'marketing-email',
  name: 'Marketing email',
  description: 'Product news and offers by email.',
  legalBasis: 'consent',
  dataCategories: ['contact'],
  consentLifetimeDays: 365,
});
```

## createRequest

Files a data-subject request on someone's behalf, received by phone, mail or a support ticket.

- **Permission:** `iam:privacy:handle` on the tenant.
- **Audited as:** `iam:privacy:handle`, plus `privacy:request:submit` with channel `staff`.
- **Errors:** `INVALID_INPUT` without a `subject` or a `requesterEmail`, or for a malformed email, details over 5000
  characters, more than 50 `purposeKeys` or an unknown `type` or `regulation`; `NOT_FOUND` for an unknown identity or
  purpose key.

Name the `subject`, or for someone without an account the `requesterEmail` (the request then has an `email:` subject
and must be linked with [`linkRequest`](#linkrequest) before most types can be fulfilled). With `verified` (the
`method` the handler used to confirm who is asking, and an optional `note`) the request opens at once and the privacy
contact is emailed; without it, it waits for [`verifyRequest`](#verifyrequest). `regulation` defaults to the tenant's.

```ts
await iam.api.privacy.createRequest(handler, {
  tenantId,
  type: 'erasure',
  subject: { identityId },
  verified: { method: 'Call-back to the number on file' },
});
```

## decide

Records your own decision on a purpose and returns its signed receipt.

- **Permission:** None beyond a person's own session of the tenant.
- **Audited as:** `privacy:consent`, with the purpose key, `granted`, version, source `self` and receipt id.
- **Errors:** `VERSION_CONFLICT` (409) when `version` is not the purpose's current version; `INVALID_INPUT` for a
  purpose with a basis other than consent or legitimate interests, a non-boolean `granted`, or a malformed `method` or
  `evidence`; `CONFLICT` (409) when granting an archived purpose; `NOT_FOUND` for an unknown purpose;
  `ACCESS_DENIED` and `IMPERSONATION_RESTRICTED` for anything but a person's own session.

`granted: true` consents, or withdraws an objection to a legitimate-interest purpose; `false` withdraws consent, opts
out, or objects. Pass the `version` you showed the person (from `mine`), so nobody agrees to text they were not shown.
`method` (a short label, `self-service` by default) and `evidence` (up to 2000 characters) are kept in the history with
the client's IP address and user agent. The decision applies to `principal.consents` from the next check.

```ts
const receipt = await iam.api.privacy.decide(session, {
  tenantId,
  purposeKey: 'marketing-email',
  version: 1,
  granted: true,
  evidence: 'Signup form v3',
});
```

## deletePurpose

Deletes a purpose nobody has decided on yet.

- **Permission:** `iam:privacy:manage` on the purpose.
- **Audited as:** `iam:privacy:manage`.
- **Errors:** `RESOURCE_IN_USE` (409) once any decision is recorded for it; `NOT_FOUND` when the purpose is not in this
  tenant.

A purpose with recorded decisions is kept as proof of what people agreed to: archive it with
[`updatePurpose`](#updatepurpose) (`archived: true`) instead.

## downloadExport

Returns the export an access or portability request produced.

- **Permission:** None for the person it is about, from their own session; otherwise `iam:privacy:handle` on the
  request, `iam:identities:read` on the account when the request is about one, and a recent sign-in.
- **Audited as:** `privacy:export:download`, with `by: 'subject'` or `'handler'`; refusals as `deny` on the missing
  action.
- **Errors:** `NOT_FOUND` when the request has no export or the export has expired; `ACCESS_DENIED` without the
  permissions; `RECENT_AUTH_REQUIRED` for a handler without a recent sign-in.

The result is `number`, `createdAt`, `expiresAt`, `sha256` (of the canonical JSON, so a copy handed over can be
checked later) and `data`. Exports stay downloadable for the tenant's `exportLifetimeDays` (14 by default), and
`iam.sweepExpired()` deletes them afterwards. People without an account cannot sign in, so a handler downloads theirs
and delivers it another way.

## extendRequest

Extends an open request's deadline once by the regulation's extension, telling the subject why.

- **Permission:** `iam:privacy:handle` on the request.
- **Audited as:** `iam:privacy:handle`, plus `privacy:request:extend` with the new `dueAt`.
- **Errors:** `INVALID_TRANSITION` (409) when the request is not open; `CONFLICT` (409) when it was already extended or
  its regulation allows no extension (LGPD); `INVALID_INPUT` for an empty reason or one over 2000 characters.

GDPR and UK GDPR add 60 days, CCPA 45, PIPEDA and `other` 30. The subject is emailed (`privacy-request-update`) and sees
the reason on their privacy page. Deadline reminders start over.

## filterSubjects

Splits up to 1000 subjects into those a purpose may be processed for and those it may not.

- **Permission:** `iam:privacy:check` on the tenant.
- **Audited as:** `iam:privacy:check`.
- **Errors:** `INVALID_INPUT` for more than 1000 subjects or a malformed one; `NOT_FOUND` for an unknown purpose.

The result is `purposeKey`, `allowed` (the subjects as you passed them) and `refused` (each with its `reason`, or
`UNKNOWN_SUBJECT` for an identity that does not exist or was deleted). Use it in batch jobs such as a marketing send.

```ts
const { allowed } = await iam.api.privacy.filterSubjects(mailerKey, {
  tenantId,
  purposeKey: 'marketing-email',
  subjects: customers.map((customer) => ({ externalId: customer.id })),
});
```

## fulfilRequest

Completes an open request by doing what it asks, and emails the subject.

- **Permission:** `iam:privacy:handle` on the request; access and portability also `iam:identities:read`, and erasure
  `iam:identities:delete`, on the account the request is about.
- **Audited as:** `iam:privacy:handle` and `privacy:request:complete` with the `actions`; an erasure also
  `privacy:erasure` and, when it deletes an account, `identity:delete` with `erasure: true`.
- **Errors:** `INVALID_TRANSITION` (409) for a request still `pending-verification` or already closed; `INVALID_INPUT`
  for a request other than rectification with an `email:` subject (link it first) or a rectification without a
  `note`; `LEGAL_HOLD` (409) for an erasure under a legal hold; `RECENT_AUTH_REQUIRED` for access, portability and
  erasure without a recent sign-in; `ACCESS_DENIED` without the directory permission; identity deletion errors such as
  `LAST_OWNER`.

What each type does:

- `access` builds a full export (profile, groups, access, sessions, sign-ins, MFA and passkeys, linked sign-ins,
  agreements, onboarding, access requests, consents and their history, processing purposes, privacy requests, and the
  person's audited activity when the handler may read the audit log, `activityOmitted: true` otherwise);
  `portability` builds one of what the person provided.
- `erasure` deletes the account, renames the tombstone "Erased person" and removes its remaining details, deletes
  sign-in records, devices, onboarding progress, queued messages, consent decisions, restrictions and exports, redacts
  the consent history and the subject's requests, and for an application subject leaves a suppression marker so later
  checks answer `ERASED`.
- `restriction` restricts processing of the subject.
- `objection` records a withdrawal for each purpose in `purposeKeys`, or every consent and legitimate-interest purpose;
  `opt-out` for each named purpose, or every opt-out consent purpose.
- `rectification` is done by hand; the `note` says what was corrected.

The result lists what was done in `actions`, such as `export:full`, `consents-withdrawn:3`, `restricted`,
`rectified`, `account-deleted`, `history-redacted:2` or `nothing-held`. The subject is emailed at the address they had
before any erasure.

```ts
const done = await iam.api.privacy.fulfilRequest(handler, { tenantId, requestId });
```

## getRequest

Returns one request with the subject's legal hold and restriction status.

- **Permission:** `iam:privacy:read` on the request.
- **Audited as:** `iam:privacy:read`.
- **Errors:** `NOT_FOUND` when the request is not in this tenant.

The request carries its timeline (`events`), `overdue`, `subjectName` for an existing account, and `legalHold` and
`restricted` for the subject. Confirmation tokens are never returned.

## getSettings

Returns the tenant's privacy settings with the statutory windows.

- **Permission:** `iam:privacy:read` on the tenant.
- **Audited as:** `iam:privacy:read`.

The result is `contactEmail`, `contactName`, `defaultRegulation`, `responseDays`, `publicIntake`, `exportLifetimeDays`
and `statutory` (each regulation's response and extension days) for display beside the tenant's own.

## history

Lists a subject's recorded decisions, newest first.

- **Permission:** `iam:privacy:read` on the tenant.
- **Audited as:** `iam:privacy:read`.
- **Errors:** `NOT_FOUND` for an unknown identity; `INVALID_INPUT` for a malformed subject or purpose key.

At most 1000 entries, optionally for one `purposeKey`, with source, method, evidence, IP address and user agent.
Deleted accounts are accepted, and entries redacted by erasure are marked `redacted` without evidence, IP address or
user agent.

## importDecisions

Imports up to 500 consent decisions from another system in one transaction.

- **Permission:** `iam:privacy:record` on the tenant.
- **Audited as:** `iam:privacy:record`, plus one `privacy:consent-import` with the count, how many became current, and
  the purpose keys.
- **Errors:** `INVALID_INPUT` for an empty list or more than 500 decisions, an entry without `version` or with a
  `recordedAt` in the future, a non-boolean `granted`, or a purpose without a say for the person; `NOT_FOUND` for an
  unknown purpose or identity; `CONFLICT` (409) for a grant on an archived purpose.

It is all or nothing. Each entry follows [`record`](#record) with source `import`: `recordedAt` and the `version` the
person decided on are required, so an imported grant never counts for newer text. Every entry joins the history, but
one older than the subject's current decision does not replace it. The result is `imported` and `current`.

## linkRequest

Links a request known only by an email address to the account or application subject it is about.

- **Permission:** `iam:privacy:handle` on the request, and `iam:identities:read` on the account when linking to one.
- **Audited as:** `iam:privacy:handle`, plus `privacy:request:link` with `subjectKind` (`account` or `external`).
- **Errors:** `CONFLICT` (409) when the request already has a subject; `INVALID_TRANSITION` (409) when it is closed;
  `NOT_FOUND` for an unknown request or identity; `ACCESS_DENIED` without `iam:identities:read`.

A public request from an address that matches no account, or a staff request filed with only a `requesterEmail`,
cannot be fulfilled until the handler has established who it is about: answering "nothing held" while an account
exists under another address would be wrong. Link it, or decline it with [`rejectRequest`](#rejectrequest) and reason
`no-data`. The optional `note` goes on the timeline.

```ts
await iam.api.privacy.linkRequest(handler, {
  tenantId,
  requestId,
  subject: { identityId },
  note: 'Same person, second address',
});
```

## liftRestriction

Ends a restriction of processing for a subject.

- **Permission:** `iam:privacy:handle` on the tenant.
- **Audited as:** `iam:privacy:handle`, plus `privacy:restriction:lift`.
- **Errors:** `NOT_FOUND` when the subject has no restriction or is unknown.

Tell the person before lifting a restriction (GDPR Art. 18(3)); lifting sends no email.

## listConsents

Lists current decisions, newest first, each with its state.

- **Permission:** `iam:privacy:read` on the tenant.
- **Audited as:** `iam:privacy:read`.
- **Errors:** `NOT_FOUND` for an unknown purpose or identity; `INVALID_INPUT` for a `limit` outside 1 to 1000.

Filter by `purposeKey`, `subject` or `granted`; page with `limit` (100 by default) and `offset`. The result is `total`
and `consents`, each with its source, method, expiry, receipt id and `state`.

## listHolds

Lists the tenant's legal holds, newest first.

- **Permission:** `iam:privacy:read` on the tenant.
- **Audited as:** `iam:privacy:read`.

Each hold carries its subject, `reason`, who placed it and when, `expiresAt` when set, and `active` (it has not
lapsed).

## listPurposes

Lists the tenant's purposes by name.

- **Permission:** `iam:privacy:read` on the tenant.
- **Audited as:** `iam:privacy:read`.

Archived purposes are left out unless `includeArchived: true`.

## listRequests

Lists requests, open ones first by deadline, then the newest.

- **Permission:** `iam:privacy:read` on the tenant.
- **Audited as:** `iam:privacy:read`.
- **Errors:** `INVALID_INPUT` for an unknown `status` or `type`, or a `limit` outside 1 to 500.

Filter by `status`, `type`, `assigneeId`, `subject` or `overdue: true`; page with `limit` (100 by default) and
`offset`. The result is `total` and `requests`, each with `overdue` and `subjectName` for an existing account.

## listRestrictions

Lists subjects whose processing is restricted, newest first.

- **Permission:** `iam:privacy:read` on the tenant.
- **Audited as:** `iam:privacy:read`.

Suppression markers left by the erasure of an application subject are listed too, with `erased: true`.

## mine

Returns your privacy page: every purpose with your decision and its effect, your requests, and the privacy contact.

- **Permission:** None beyond a person's own session of the tenant.
- **Audited as:** Not audited; it only reads.
- **Errors:** `ACCESS_DENIED` for anything but a person's own session of the tenant; `IMPERSONATION_RESTRICTED` while
  impersonating; `TENANT_INACTIVE` for a suspended tenant.

`purposes` lists the live purposes, the ones you decide on first, each with `decidable`, `state` (`allowed` and
`reason`) and your `consent` when recorded. `restricted` says whether processing of your data is restricted.
`requests` shows your requests without internal notes and assignments. `contact` is the privacy contact, when set.

## myHistory

Lists your own recorded decisions, newest first.

- **Permission:** None beyond a person's own session of the tenant.
- **Audited as:** Not audited; it only reads.

At most 500 entries, optionally for one `purposeKey`, with the evidence, IP address and user agent recorded with each.

## myReceipt

Returns the signed receipt of one of your own decisions.

- **Permission:** None beyond a person's own session of the tenant.
- **Audited as:** Not audited; it only reads.
- **Errors:** `NOT_FOUND` when the receipt is not one of your decisions.

Receipts are rebuilt from the history and signed with the current deployment secret, so this also gives a fresh copy
after a secret rotation.

## placeHold

Places a legal hold on a subject: erasure, and every deletion of their account, is refused until it is released.

- **Permission:** `iam:privacy:manage` on the tenant.
- **Audited as:** `iam:privacy:manage`, plus `privacy:hold:place` with the hold id and expiry.
- **Errors:** `NOT_FOUND` for an unknown or deleted identity; `INVALID_INPUT` for an empty reason or one over 2000
  characters, or an `expiresAt` that is not in the future or is more than ten years away.

While a hold is live, `fulfilRequest` refuses erasure and identity deletion refuses the person (`LEGAL_HOLD`, 409),
whether an administrator (`identities.delete`) or an erasure request asks; offboarding and SCIM deprovisioning only
disable accounts, so they keep the data anyway. Holds do not stop processing or other requests. `expiresAt` makes the
hold lapse on its own.

```ts
await iam.api.privacy.placeHold(admin, {
  tenantId,
  subject: { identityId },
  reason: 'Litigation 2026-17',
});
```

## record

Records a consent decision for a person of the tenant or an application subject, and returns its receipt.

- **Permission:** `iam:privacy:record` on the tenant.
- **Audited as:** `iam:privacy:record`, plus `privacy:consent` with the purpose key, `granted`, version, source,
  receipt id and `externalId`.
- **Errors:** `INVALID_INPUT` for a non-boolean `granted`, a `recordedAt` without `source: 'import'`, an import without
  `version`, a `version` above the current one, a malformed subject, `method` or `evidence`, or a purpose with a basis
  other than consent or legitimate interests; `CONFLICT` (409) for a grant on an archived purpose; `NOT_FOUND` for an
  unknown purpose or identity.

`source` is `api` (the default), `admin` for a decision captured elsewhere, or `import` for one moved from another
system with its original `recordedAt` and `version`. `ip` and `userAgent` record where the decision was captured. The
result is the receipt plus `current`, false when an older imported decision did not replace a newer one. Server code
records decisions without a credential with `iam.privacy.record`, audited with actor `application`.

```ts
await iam.api.privacy.record(apiKey, {
  tenantId,
  subject: { externalId: 'cus_100' },
  purposeKey: 'marketing-email',
  granted: true,
  method: 'banner',
  ip: '203.0.113.9',
});
```

## rejectRequest

Declines an open or unverified request with a reason the subject is emailed.

- **Permission:** `iam:privacy:handle` on the request.
- **Audited as:** `iam:privacy:handle`, plus `privacy:request:reject` with the reason.
- **Errors:** `INVALID_TRANSITION` (409) when the request is closed; `INVALID_INPUT` for an unknown reason or a note
  over 2000 characters.

Reasons are `unverified`, `unfounded`, `excessive`, `exempt` (for example a legal obligation to keep the data, or a
legal hold), `duplicate`, `no-data` (nothing is held about the person) and `other`. The email names the reason and
tells the person they may complain to a data protection authority; the optional `note` appears on their privacy page.

## releaseHold

Releases a legal hold.

- **Permission:** `iam:privacy:manage` on the hold.
- **Audited as:** `iam:privacy:manage`, plus `privacy:hold:release`.
- **Errors:** `NOT_FOUND` when the hold is not in this tenant.

## submitPublic

Files a request from someone without an account, from a public form, when the organization turned on public intake.

- **Permission:** None: public, tenant-bound (on an organization's own address `tenantId` may be left out).
- **Audited as:** `privacy:request:submit` with channel `public`, actor `public-intake`.
- **Errors:** `NOT_FOUND` while `publicIntake` is off or the tenant is inactive; `DELIVERY_REQUIRED` without an email
  delivery callback; `RATE_LIMITED` (429) past 3 requests per address or 500 per organization in a rate-limit window
  (and the per-IP limit when `rateLimits.ipAttempts` is set); `INVALID_INPUT` for a malformed email, name, `externalId`
  or details.

The requester is emailed a confirmation link (`privacy-request-verify`) and nobody handles the request until they
confirm it with [`confirmPublic`](#confirmpublic); unconfirmed requests lapse after seven days. The result is only the
reference `number` and `status`. `externalId` names the identifier the application knows the requester by; such a
request also needs a handler's [`verifyRequest`](#verifyrequest).

```ts
await client.privacy.submitPublic({ tenantId, type: 'access', email: 'alice@example.com' });
```

## submitRequest

Files a data-subject request for yourself; signing in verified who you are, so its deadline starts at once.

- **Permission:** None beyond a person's own session of the tenant.
- **Audited as:** `privacy:request:submit` with channel `self-service`.
- **Errors:** `CONFLICT` (409) when you already have an open request of this type; `NOT_FOUND` for an unknown purpose
  key; `INVALID_INPUT` for an unknown `type` or `regulation`, details over 5000 characters or more than 50
  `purposeKeys`.

The request opens with verification method `authenticated-session`, and the privacy contact is emailed.
`purposeKeys` names the purposes an objection or opt-out is about. The result is the request as you see it in `mine`.

```ts
await iam.api.privacy.submitRequest(session, { tenantId, type: 'access' });
```

## summary

Returns consent counts per purpose, the request queue, holds and restrictions at a glance.

- **Permission:** `iam:privacy:read` on the tenant.
- **Audited as:** `iam:privacy:read`.

Per purpose: subjects it may be processed for on the strength of a recorded decision (`granted`), `withdrawn`
(including objections), `expired` and `outdated`. Requests: `pendingVerification`, `open`, `overdue`, `dueSoon`
(within seven days), `completedLast30Days`, `medianDaysToClose` over the last 90 days, and open requests `byType`.
Plus live `holds` and `restrictions`.

## updatePurpose

Edits a purpose, optionally publishing the change as a new version or archiving it.

- **Permission:** `iam:privacy:manage` on the purpose.
- **Audited as:** `iam:privacy:manage`.
- **Errors:** `INVALID_INPUT` for a changed `key`, a changed `legalBasis` or `mode` without `newVersion: true`, or the
  validation of `createPurpose`; `NOT_FOUND` when the purpose is not in this tenant.

Fields you leave out keep their values, and `null` clears `retentionDays` or `consentLifetimeDays`. `newVersion: true`
increments the version: opt-in grants for older versions stop counting (unless `reconsentOnVersion` is false) and
`decide` needs the new version. `archived: true` stops all processing for the purpose and hides it from people; the
decisions stay.

```ts
await iam.api.privacy.updatePurpose(admin, {
  tenantId,
  purposeId,
  description: 'Product news, offers and partner offers by email.',
  newVersion: true,
});
```

## updateSettings

Changes the privacy contact, default regulation, internal response windows, public intake and export lifetime.

- **Permission:** `iam:privacy:manage` on the tenant.
- **Audited as:** `iam:privacy:manage`.
- **Errors:** `INVALID_INPUT` for a malformed email, an unknown regulation, a `responseDays` value outside 1 to the
  statutory window, or an `exportLifetimeDays` outside 1 to 90; `DELIVERY_REQUIRED` when turning on `publicIntake`
  without an email delivery callback.

`contactEmail` (the data protection officer or privacy team) receives new requests and deadline reminders and is shown
to people; `null` clears it, `contactName` and `responseDays`. `responseDays` sets shorter internal windows per
regulation, never longer than the law's.

```ts
await iam.api.privacy.updateSettings(admin, {
  tenantId,
  contactEmail: 'dpo@acme.test',
  responseDays: { gdpr: 20 },
  publicIntake: true,
});
```

## verifyReceipt

Checks a consent receipt someone presents against the signature and the history.

- **Permission:** `iam:privacy:read` on the tenant.
- **Audited as:** `iam:privacy:read`.

The result is `valid: true` with `current` (still the subject's latest decision on the purpose) and `redacted` when
erasure redacted the entry, or `valid: false` with a `reason`: `SIGNATURE_INVALID` (not signed by this deployment for
this tenant, or altered), `NOT_RECORDED` or `CONTENT_MISMATCH`. Signatures made with any of `previousSecrets` still
verify during a secret rotation.

## verifyRequest

Records how the requester's identity was confirmed, which opens the request and starts its deadline.

- **Permission:** `iam:privacy:handle` on the request.
- **Audited as:** `iam:privacy:handle`, plus `privacy:request:verify` with the method.
- **Errors:** `INVALID_TRANSITION` (409) when the request is not `pending-verification`; `INVALID_INPUT` for an empty
  method or one over 120 characters, or a note over 2000.

The privacy contact is emailed once the request opens. Use it for staff-filed requests created without `verified`,
and for public requests naming an `externalId` once you have checked the requester owns it.

```ts
await iam.api.privacy.verifyRequest(handler, {
  tenantId,
  requestId,
  method: 'Customer portal sign-in',
});
```
