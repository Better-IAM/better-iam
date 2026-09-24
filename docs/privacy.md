# Privacy and consent

Privacy management keeps an organization's records of processing next to the people they are about. It covers what
GDPR, UK GDPR, CCPA/CPRA, LGPD and PIPEDA ask of a data controller:

- **Purposes.** The reasons the organization processes personal data (`marketing-email`, `product-analytics`,
  `billing`), each with its lawful basis, the categories of data it uses and how long they are kept.
- **Consent.** Each person's decision on each purpose, recorded by the person, by an administrator, or by the
  application for its own customers, with a signed receipt and an append-only history.
- **Data-subject requests.** Access, portability, erasure, rectification, restriction, objection and opt-out requests
  with statutory deadlines, identity verification, automated fulfilment, reminders and emails.
- **Legal holds** that stop erasure while litigation needs the data, and **restriction of processing**.

Applications ask "may I process this purpose for this person right now?" with `privacy.check` (or `iam.privacy.check`
on the server), and policies see the answer as `principal.consents`, so consent can gate access like any other
condition. Everything lives in the `privacy` API group (`POST /api/iam/privacy/{method}`, `client.privacy.*` in the
browser).

## Purposes and legal bases

A purpose is created at version 1 in one tenant:

```ts
await iam.api.privacy.createPurpose(admin, {
  tenantId,
  key: 'marketing-email',
  name: 'Marketing email',
  description: 'Product news and offers by email.',
  legalBasis: 'consent',
  dataCategories: ['contact'],
  retentionDays: 730,
});

await iam.api.privacy.createPurpose(admin, {
  tenantId,
  key: 'data-sharing',
  name: 'Sharing with partners',
  description: 'Sharing contact data with advertising partners.',
  legalBasis: 'consent',
  mode: 'opt-out', // CCPA "do not sell or share": allowed until the person opts out
});
```

- `key` is permanent: 1 to 64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter. Policies
  and application code refer to purposes by key.
- `name` (up to 120 characters) and `description` (plain text, up to 5000) are what people see when they decide.
- `dataCategories` holds up to 32 lowercase identifiers such as `contact`, `usage` or `location`, and
  `retentionDays` (from 1 to 36500) says how long data for the purpose is kept. Both are for records of processing
  and appear in access exports.
- A tenant holds at most 200 purposes.

The legal basis (GDPR Art. 6) decides whether a person has a say, and how a missing decision is read:

| `legalBasis`           | Who decides                     | Processing is allowed                                                   |
| ---------------------- | ------------------------------- | ----------------------------------------------------------------------- |
| `consent`, `opt-in`    | The person: opt-in consent      | Only with a recorded grant for the current version that has not lapsed. |
| `consent`, `opt-out`   | The person: opt-out             | Until the person opts out (withdraws).                                  |
| `legitimate-interests` | The person may object           | Until the person objects.                                               |
| `contract`             | Nobody: no decision is recorded | Always, unless processing is restricted.                                |
| `legal-obligation`     | Nobody                          | Always, even while processing is restricted.                            |
| `vital-interests`      | Nobody                          | Always, even while processing is restricted.                            |
| `public-task`          | Nobody                          | Always, unless processing is restricted.                                |

`mode` defaults to `opt-in`; only consent purposes can be `opt-out`. Recording a decision on a purpose with another
basis fails with `INVALID_INPUT`, because the person's choice would change nothing.

`updatePurpose` edits a purpose; fields you leave out keep their values and `null` clears `retentionDays` or
`consentLifetimeDays`. `archived: true` stops all processing for the purpose (every check answers `PURPOSE_ARCHIVED`,
and people no longer see it) while keeping every decision. `deletePurpose` removes a purpose only while nobody has
decided on it; once decisions are recorded it answers `RESOURCE_IN_USE`, so archive it instead and keep the proof.

## Versions and re-consent

A material change to a purpose, such as new partners or a new use of the data, is published as the next version:

```ts
await iam.api.privacy.updatePurpose(admin, {
  tenantId,
  purposeId: marketing.id,
  description: 'Product news, offers and partner offers by email.',
  newVersion: true,
});
```

Opt-in grants given to an older version then stop counting (`CONSENT_OUTDATED`), so people are asked again. Set
`reconsentOnVersion: false` on a purpose to keep older grants valid across versions. Withdrawals, opt-outs and
objections always carry over. Changing a purpose's `legalBasis` or `mode` is always material (turning opt-in into
opt-out makes everyone who was never asked processable): without `newVersion: true` it fails with `INVALID_INPUT`.

People decide on the version they were shown: `decide` takes `version` and answers `VERSION_CONFLICT` (409) when the
purpose changed in the meantime, so nobody agrees to text they did not see.

## Consent lifetime

`consentLifetimeDays` (1 to 3650, consent purposes only) makes grants lapse: a grant recorded now expires that many
days later (`expiresAt` on the decision) and then answers `CONSENT_EXPIRED` until the person grants again. Cookie
consent is often 365 days. The expiry is fixed when a grant is recorded, so changing the lifetime applies to new
grants, and imported grants count from their `recordedAt`. Only opt-in grants lapse; withdrawals never do.

## How a decision is read

`consentState` (exported from `@better-iam/server`) turns a purpose, the subject's current decision and whether their
processing is restricted (or the subject was erased) into `{ allowed, reason }`. The first rule that applies wins:

| Reason                 | Allowed | When                                                                                              |
| ---------------------- | ------- | ------------------------------------------------------------------------------------------------- |
| `PURPOSE_ARCHIVED`     | no      | The purpose is archived.                                                                          |
| `RESTRICTED`           | no      | Processing is restricted, and the basis is not `legal-obligation` or `vital-interests`.           |
| `ERASED`               | no      | The application subject was erased, and the basis is not `legal-obligation` or `vital-interests`. |
| `OBJECTED`             | no      | A legitimate-interest purpose the person objected to.                                             |
| `LEGITIMATE_INTERESTS` | yes     | A legitimate-interest purpose without an objection.                                               |
| `LEGAL_BASIS`          | yes     | `contract`, `legal-obligation`, `vital-interests` or `public-task`.                               |
| `CONSENT_WITHDRAWN`    | no      | A consent purpose the person declined, withdrew from or opted out of.                             |
| `NOT_OPTED_OUT`        | yes     | An opt-out purpose without an opt-out.                                                            |
| `NO_CONSENT`           | no      | An opt-in purpose without a decision.                                                             |
| `CONSENT_EXPIRED`      | no      | The grant passed its `expiresAt`.                                                                 |
| `CONSENT_OUTDATED`     | no      | The grant is for an older version and the purpose asks again on new versions.                     |
| `CONSENT_GIVEN`        | yes     | A live grant for the current version (or an older one the purpose still accepts).                 |

## People's own choices

People manage their privacy from their own signed-in session of the organization, without any permission. Role
sessions, API keys, session tokens and agents acting for them are refused (`ACCESS_DENIED`), and so are
administrators "viewing as" them (`IMPERSONATION_RESTRICTED`). Only people are data subjects: service accounts and
agents have no privacy choices.

```ts
const mine = await iam.api.privacy.mine(session, { tenantId });
// mine.purposes: every live purpose with `decidable`, `state` ({ allowed, reason }) and the person's `consent`
// mine.restricted, mine.requests (their data-subject requests), mine.contact (the privacy contact)

const receipt = await iam.api.privacy.decide(session, {
  tenantId,
  purposeKey: 'marketing-email',
  version: mine.purposes.find((purpose) => purpose.key === 'marketing-email')!.version,
  granted: true,
  evidence: 'Signup form v3',
});
```

`granted: true` consents (or withdraws an objection); `granted: false` withdraws consent, opts out, or objects to a
legitimate-interest purpose. Granting an archived purpose is refused (`CONFLICT`); withdrawing is not. `method` (a
short label, `self-service` by default) and `evidence` (what the person saw, up to 2000 characters) are kept in the
history with the client's IP address and user agent. `myHistory` lists the person's decisions, newest first (at most
500), and `myReceipt` returns the signed receipt of one of them.

In React, `usePrivacy({ tenantId })` from `@better-iam/react` returns the page (`privacy`), `pending` (the opt-in
purposes still waiting for an answer, for a consent banner), `decide(purpose, granted)` (which records the choice for
the version the page showed, so a changed purpose answers `VERSION_CONFLICT`), `request(type, input?)`, `cancel(requestId)` and `refresh()`.

## Receipts and history

Every decision appends an entry to the consent history and returns a **consent receipt** the subject can keep:

```json
{
  "version": 1,
  "receiptId": "…",
  "tenantId": "…",
  "subject": "identity:…",
  "purpose": {
    "key": "marketing-email",
    "name": "Marketing email",
    "version": 1,
    "legalBasis": "consent"
  },
  "granted": true,
  "recordedAt": 1790000000000,
  "source": "self",
  "method": "self-service",
  "signature": "…"
}
```

- The signature is an HMAC-SHA256 over the receipt's canonical JSON, with a key derived from the deployment `secret`.
- Receipts are not stored: they are rebuilt from the history entry, which keeps the purpose's name and basis as they
  were, so renaming a purpose later does not change old receipts.
- `source` is `self`, `admin`, `api`, `import` or `request` (written while fulfilling a data-subject request).

`verifyReceipt` (`iam:privacy:read`) checks a receipt someone presents. It returns `{ valid: true, current }`, where
`current` says whether it is still the subject's latest decision on the purpose, plus `redacted: true` when erasure
redacted the entry. Otherwise it returns `{ valid: false, reason }`, where `reason` is `SIGNATURE_INVALID` (not signed
by this deployment for this tenant, or altered), `NOT_RECORDED` (no such decision) or `CONTENT_MISMATCH` (signed, but
different from the history). Verification accepts the current `secret` and every one in `previousSecrets`, so receipts
keep verifying while the deployment secret rotates. Once an old secret leaves `previousSecrets`, `myReceipt` gives the
person a fresh copy signed with the current one.

`history` (`iam:privacy:read`) lists a subject's decisions, newest first (at most 1000), with the evidence, IP address
and user agent. `listConsents` lists current decisions, filtered by purpose, subject or outcome, each with its state.
The history is append-only: nothing edits it except erasure, which removes the evidence, IP address and user agent
and marks the entry `redacted`.

## Consent the application records

Applications often need consent for people who have no account in Better IAM: customers of a shop, newsletter
subscribers, website visitors. Every method that takes a subject accepts either `{ identityId }` (a person of the
tenant) or `{ externalId }` (1 to 256 visible characters the application chooses: a customer number, a visitor ID, an
email hash).

```ts
// An API key allowed iam:privacy:record records a cookie banner choice.
await iam.api.privacy.record(apiKey, {
  tenantId,
  subject: { externalId: 'cus_100' },
  purposeKey: 'marketing-email',
  granted: true,
  method: 'banner',
  ip: '203.0.113.9',
});
```

`record` takes `source: 'api'` (the default) or `'admin'` for a decision captured elsewhere, such as a signed paper
form. It records decisions on the current version unless `version` names an earlier one.

**Imports.** Moving consent records from another system, use `source: 'import'` with the original `recordedAt`, or
`importDecisions` for up to 500 decisions in one transaction (all or nothing). Every imported decision must state the
purpose `version` the person decided on (`INVALID_INPUT` otherwise), so an old grant never counts for today's text.
Imported decisions are added to the history, but an older one never replaces a newer current decision: the result of
`record` says so with `current`, and `importDecisions` returns `{ imported, current }`.

**Checking.** `check` (`iam:privacy:check`) answers for one subject and purpose; `filterSubjects` splits up to 1000
subjects into `allowed` and `refused` (with the reason, or `UNKNOWN_SUBJECT` for an identity that does not exist or
was deleted), for batch jobs such as a marketing send. `audience` (`iam:privacy:read`) lists everyone a purpose may
be processed for right now: every active person of the tenant for which the purpose is allowed, and every application
subject with a decision that allows it, paged by `limit` (up to 1000) and `offset`. People's emails and names are
included only when the caller may also read identities (`iam:identities:read`); otherwise they are listed by ID.

```ts
const { allowed, refused } = await iam.api.privacy.filterSubjects(mailerKey, {
  tenantId,
  purposeKey: 'marketing-email',
  subjects: recipients.map((recipient) => ({ externalId: recipient.customerId })),
});
```

**Server code** checks and records without a credential through `iam.privacy`:

```ts
const { allowed, reason } = await iam.privacy.check({
  tenantId,
  subject: { externalId: 'cus_100' },
  purposeKey: 'product-analytics',
});

await iam.privacy.record({
  tenantId,
  subject: { externalId: visitorId },
  purposeKey: 'cookies.ads',
  granted: false,
  method: 'cookie-banner',
  evidence: 'Banner text v4',
  ip,
  userAgent,
});
```

`iam.privacy.check` is not audited. `iam.privacy.record` records the decision on the current version with source
`api`, attributed to `application`, and is audited as `privacy:consent` with actor `application`. Like the other
`iam.*` runtimes it is not reachable over HTTP, so keep it to trusted code.

`summary` (`iam:privacy:read`) counts, per purpose, the subjects it may be processed for on the strength of a
recorded decision (`granted`), and those withdrawn or objected, expired and outdated, alongside the request queue,
live holds and restrictions.

## Consent in policies

Every decision for a person in their own organization can read `principal.consents`: the sorted keys of the consent
and legitimate-interest purposes that may be processed for them right now (granted, not opted out, not objected to,
not restricted). Purposes with other bases never appear, because the person has no say in them. The server computes
it only when a document names the key.

```ts
await iam.api.roles.create(admin, {
  tenantId,
  name: 'Newsletter reader',
  document: {
    version: 1,
    statements: [
      {
        effect: 'allow',
        actions: ['documents:read'],
        resources: ['*'],
        conditions: { ArrayContains: { 'principal.consents': ['marketing-email'] } },
      },
    ],
  },
});
```

A decision recorded with `decide` applies from the next authorization check. Assumed roles and the keys of service
accounts and agents see an empty list, so a condition that requires a consent never matches for them. The key is
server-owned: `resolveContext` and plugins cannot supply it, and identity attributes cannot be named `consents`.

## Data-subject requests

A data-subject request (DSR, or DSAR for access) carries a reference such as `DSR-7K2M9QX4`, a type, the regulation it
is answered under, and a deadline.

| Type            | The person asks                                    | Fulfilling it                                                               |
| --------------- | -------------------------------------------------- | --------------------------------------------------------------------------- |
| `access`        | A copy of their personal data                      | Builds a full export.                                                       |
| `portability`   | The data they provided, in a portable format       | Builds an export of what the person provided.                               |
| `erasure`       | Deletion of their data                             | Deletes the account and erases privacy records. Refused under a legal hold. |
| `rectification` | Correction of their data                           | Done by hand; completing it needs a `note` saying what was corrected.       |
| `restriction`   | Processing paused (GDPR Art. 18)                   | Restricts processing of the subject.                                        |
| `objection`     | An end to processing based on legitimate interests | Withdraws the named purposes, or every purpose the person has a say in.     |
| `opt-out`       | No sale or sharing of their data (CCPA)            | Withdraws the named purposes, or every opt-out consent purpose.             |

`purposeKeys` (up to 50 existing purpose keys) names the purposes an objection or opt-out is about. A restriction
always covers the whole subject.

### Regulations and deadlines

Each request is answered under one regulation (`regulation` on the request, or the tenant's `defaultRegulation`,
`gdpr` by default). The response window starts when the requester's identity is verified:

| `regulation` | Response window | Extension | Source                                  |
| ------------ | --------------- | --------- | --------------------------------------- |
| `gdpr`       | 30 days         | 60 days   | One month, plus two months (Art. 12(3)) |
| `uk-gdpr`    | 30 days         | 60 days   | As GDPR                                 |
| `ccpa`       | 45 days         | 45 days   | Cal. Civ. Code 1798.130                 |
| `lgpd`       | 15 days         | none      | Art. 19                                 |
| `pipeda`     | 30 days         | 30 days   | s. 8(3)                                 |
| `other`      | 30 days         | 30 days   |                                         |

The table is exported as `regulationDeadlines` from `@better-iam/server`. An organization can answer sooner than the
law requires: `responseDays` in the privacy settings sets a shorter internal window per regulation (never longer than
the statutory one). Extensions always add the statutory extension.

### Lifecycle

- `pending-verification`: received, but nobody has confirmed who is asking yet, so no deadline runs. `verifyRequest`
  or `confirmPublic` opens it (a public request naming an `externalId` still needs `verifyRequest` after its address
  is confirmed).
- `open`: verified. `receivedAt` is when the window started and `dueAt` when it ends; `overdue` is true once `dueAt`
  has passed. `fulfilRequest` completes it.
- `completed`: fulfilled, with what was done in `actions`.
- `rejected`: refused by `rejectRequest`, from `pending-verification` or `open`.
- `cancelled`: withdrawn by the person (`cancelMyRequest`), or a public request whose address nobody confirmed within
  seven days.

Closed requests carry `closedAt` and `closedBy`.

Every step is kept on the request's timeline (`events`, the newest 100). People see their own requests in `mine`
without internal notes and assignments; the note given with a rejection, an extension or a completion is shown to
them, attributed to the organization.

### Filing a request

**Self-service.** A person files a request from their own session with `submitRequest`. Signing in verified who they
are, so the request opens at once (verification method `authenticated-session`) and the privacy contact is emailed.
`regulation` defaults to the tenant's, and `details` (up to 5000 characters) says what the person needs. One open
request per type is allowed at a time (`CONFLICT`), and `cancelMyRequest` withdraws one while it is being handled.

```ts
await iam.api.privacy.submitRequest(session, { tenantId, type: 'access' });
await iam.api.privacy.submitRequest(session, {
  tenantId,
  type: 'objection',
  purposeKeys: ['product-analytics'],
});
```

**Staff-filed.** A request received by phone, by mail or in a support ticket is filed with `createRequest`
(`iam:privacy:handle`), naming the `subject` or, for someone without an account, the `requesterEmail`. With `verified`
(how the handler confirmed who is asking) it opens at once; without it the request waits for `verifyRequest`, which
records the method and starts the window.

```ts
const request = await iam.api.privacy.createRequest(handler, {
  tenantId,
  type: 'erasure',
  subject: { identityId: aliceId },
  details: 'Asked by phone on 12 March.',
  verified: { method: 'call-back to the number on file' },
});
```

**Public intake.** People without an account, or who cannot sign in, can file requests from a public form when the
organization turns on `publicIntake` in its privacy settings (which needs an email delivery callback,
`DELIVERY_REQUIRED` otherwise). `privacy.submitPublic` and `privacy.confirmPublic` need no credential:

```ts
// The public form (no credential):
await client.privacy.submitPublic({
  tenantId,
  type: 'access',
  email: 'alice@example.com',
  name: 'Alice',
});
// The page the confirmation link opens:
await client.privacy.confirmPublic({ tenantId, requestId, token });
```

- `submitPublic` answers `NOT_FOUND` while public intake is off, and otherwise emails a confirmation link
  (`privacy-request-verify`). It returns only the reference and status.
- Nobody handles the request until the requester confirms their address with `confirmPublic`. A wrong, used or expired
  token answers `CONFIRMATION_INVALID`. Unconfirmed requests lapse after seven days: the deadline job cancels them.
- Once confirmed, the window starts (verification method `email-link`) and the privacy contact is emailed. When the
  address belongs to a person of the organization with a verified email, the request is linked to their account, so
  fulfilling it acts on the account.
- A requester may also name the `externalId` the application knows them by. Owning the address does not prove owning
  that identifier, so confirming only records `emailConfirmedAt` (audited as `privacy:request:email-confirmed`) and
  emails the privacy contact; the request stays `pending-verification` until a handler checks the identifier with
  `verifyRequest`, and it no longer lapses.
- Both calls are rate limited: 500 submissions per organization and 3 per email address per rate-limit window (plus
  the per-IP limit when `rateLimits.ipAttempts` is set), and 10 confirmation attempts per request (`RATE_LIMITED`).
- On an organization's own sign-in address the `tenantId` may be left out, and in a multi-region deployment only the
  organization's home region serves them.

**Requests known only by an email address.** A public request from an address that matches no account, or a staff
request filed with only a `requesterEmail`, has an `email:` subject: a hash of the address keyed with the deployment
secret, so a redacted request cannot be matched back to an address by hashing guesses. Apart from rectification (done
by hand), such a request cannot be fulfilled (`INVALID_INPUT`), because answering "nothing held" while an account
exists under another address would be wrong. Once the handler has established who it is about, `linkRequest` links
it to the account (`{ identityId }`, which also needs `iam:identities:read` on it) or the application subject
(`{ externalId }`); otherwise decline it with `rejectRequest` and reason `no-data`.

```ts
await iam.api.privacy.linkRequest(handler, {
  tenantId,
  requestId,
  subject: { identityId: aliceId },
  note: 'Same person, second address',
});
```

### Handling and fulfilling

Handlers need `iam:privacy:handle`. `listRequests` (`iam:privacy:read`) lists requests, open ones first by deadline,
filtered by `status`, `type`, `assigneeId`, `subject` or `overdue`; `getRequest` adds whether the subject is under a
legal hold (`legalHold`) and restricted (`restricted`). `assignRequest` hands a request to an active person of the
tenant (who then gets its reminders), and `addNote` adds an internal note.

`fulfilRequest` completes an open request and does what its type asks (a request still `pending-verification` is
refused with `INVALID_TRANSITION`). Access, portability and erasure are as sensitive as exporting or deleting the
account yourself, so they need a recent sign-in (`RECENT_AUTH_REQUIRED`) and a subject other than an email address:

- **Access and portability** build an export. For a request about an account, this also needs `iam:identities:read`
  on that identity (`iam/{identityId}`). The person's audited activity is included only when the handler may read the
  audit log (`iam:audit:read`); otherwise the export says `activityOmitted: true`.
- **Erasure** deletes the account and erases privacy records (below). It also needs `iam:identities:delete` on the
  identity, and is refused with `LEGAL_HOLD` while the subject is under a legal hold.
- **Restriction** restricts processing of the subject.
- **Objection** records a withdrawal (source `request`, method `request:{number}`) for each purpose in `purposeKeys`,
  or for every consent and legitimate-interest purpose when none are named. **Opt-out** does the same for every
  opt-out consent purpose. Purposes the person has no say in are skipped.
- **Rectification** is done by hand in your systems; `fulfilRequest` then needs a `note` describing what was corrected.

The completed request lists what was done in `actions` (`export:full`, `export:provided`, `restricted`,
`consents-withdrawn:3`, `rectified`, and for erasure `account-deleted`, `account-details-erased`, `consents-deleted:1`,
`history-redacted:2`, or `nothing-held`), and the subject is emailed (`privacy-request-update`).

`extendRequest` extends an open request's deadline once by the regulation's extension, with a `reason` the subject is
emailed. A second extension, or one under LGPD (which allows none), answers `CONFLICT`. `rejectRequest` refuses an open
or unverified request with a reason (`unverified`, `unfounded`, `excessive`, `exempt`, `duplicate`, `no-data`,
`other`) and an optional note; the subject is emailed the reason and told they may complain to a data protection
authority.

### Exports

Access and portability requests produce a JSON export (`format: 'better-iam.privacy-export'`, `version: 1`):

- **Access** (`scope: 'full'`) holds the profile (never secrets such as password hashes), groups, access (roles,
  direct or through a group, with end dates), sessions, sign-in summary, MFA and passkeys, linked sign-ins, accepted
  agreements, onboarding answers, access and package requests, current consents and the consent history, the
  organization's processing purposes (description, basis, data categories, retention), the person's privacy requests,
  and up to 5000 of their most recent audited actions (when the handler may read the audit log).
- **Portability** (`scope: 'provided'`) holds what the person provided: name, email, phone, attributes, onboarding
  answers and agreements, with their consents and consent history.
- For a subject without an account (an `externalId`, or an account already deleted) the export holds the consents and
  consent history, plus the processing purposes and requests for access.

The export is stored with the SHA-256 of its canonical JSON (`sha256`), so a copy handed over can be checked later,
and stays downloadable for `exportLifetimeDays` (14 by default, 1 to 90). `downloadExport` returns it to the person it
is about, from their own session, or to a handler who delivers it another way (people without an account cannot sign
in to fetch it). A handler needs `iam:privacy:handle` on the request, `iam:identities:read` on the account when the
request is about one, and a recent sign-in; refusals are audited as `deny`. Each download is counted and audited as
`privacy:export:download`. An expired export answers `NOT_FOUND`, and `iam.sweepExpired()` deletes it; the request
keeps its record.

### Erasure

Fulfilling an erasure request, in one transaction:

- deletes the account through identity deletion, the same path as `identities.delete`: credentials, sessions,
  bindings, memberships and the rest go, and the usual rules apply (for example `LAST_OWNER`);
- renames the tombstone "Erased person" and removes its remaining email, attributes, description and phone;
- deletes sign-in records, trusted devices, onboarding progress and messages still queued for the person's address;
- deletes the subject's current consent decisions and redacts their consent history (evidence, IP address and user
  agent are removed; the entries stay, marked `redacted`, as proof of what was recorded);
- deletes the subject's restriction and exports;
- for an application subject, leaves a suppression marker (a restriction with `erased: true`), so the application
  asking about the same `externalId` again gets `ERASED` rather than an opt-out purpose turning back into "allowed";
- removes the requester's email, name, details and notes from the subject's requests, this one included (`redacted`).

The person receives a last `privacy-request-update` at their old address, without a link. Deleting the account is
audited as `identity:delete` with `{ kind, erasure: true }` and no email address, so webhooks, outbound SCIM and Shared
Signals remove the account downstream as for any deletion. The request is audited as `privacy:request:complete` and
`privacy:erasure`: subscribe a [webhook](events.md) to `privacy:erasure` to erase the person's data in downstream
systems. The audit log is not rewritten; its events keep pointing at the tombstone's ID.

Deleting a person in any other way also removes their current consent decisions and restriction, but keeps the
consent history and their requests as the record of what happened.

### Deadlines and reminders

Run `iam.privacy.sendDeadlineReminders()` daily or hourly. For every open request it emails the assignee (or, without
an active assignee, the privacy contact) once when the request is due within `withinDays` (7 by default, 1 to 60) and
once when it becomes overdue, and records `privacy:request:due-soon` / `privacy:request:overdue` (actor
`deployment-operator`) so webhooks can alert too. An extension resets the reminders. The same run cancels public
requests whose address nobody confirmed within seven days. It returns `{ reminded, lapsed }`; pass `tenantId` to limit
it to one organization.

## Legal holds

A legal hold keeps a subject's data while litigation or an investigation needs it:

```ts
const hold = await iam.api.privacy.placeHold(admin, {
  tenantId,
  subject: { identityId: aliceId },
  reason: 'Litigation 2026-17',
  expiresAt: Date.parse('2027-12-31'), // optional: in the future, within ten years
});
// later
await iam.api.privacy.releaseHold(admin, { tenantId, holdId: hold.id });
```

While a hold is live, erasure of the subject is refused with `LEGAL_HOLD` (409), and so is every deletion of the
person's account: identity deletion checks for holds itself, so neither an administrator (`identities.delete`) nor an
erasure request removes what the hold keeps. Offboarding and SCIM deprovisioning only disable the account, so they keep
the data anyway. Release the hold, or reject the erasure request as `exempt`. A hold lapses at its `expiresAt`;
`listHolds` shows each one with `active`. Holds do not stop processing or other requests.

## Restriction of processing

Fulfilling a `restriction` request restricts processing of the subject (GDPR Art. 18): every check then refuses the
subject's purposes with `RESTRICTED`, including contract and public-task purposes, except `legal-obligation` and
`vital-interests`. `principal.consents` becomes empty, and the person's own page shows `restricted: true`.
`listRestrictions` (`iam:privacy:read`) lists restricted subjects, with erasure suppression markers marked
`erased: true`, and `liftRestriction` (`iam:privacy:handle`) ends a restriction. Tell the person before you lift it;
lifting sends no email.

## Settings

`getSettings` (`iam:privacy:read`) and `updateSettings` (`iam:privacy:manage`) hold one record per tenant:

| Setting              | Default | Meaning                                                                                                   |
| -------------------- | ------- | --------------------------------------------------------------------------------------------------------- |
| `contactEmail`       |         | The privacy contact (data protection officer): emailed about new requests and deadlines, shown to people. |
| `contactName`        |         | Shown with the address.                                                                                   |
| `defaultRegulation`  | `gdpr`  | The regulation of requests that name none.                                                                |
| `responseDays`       |         | Shorter internal windows per regulation, in days (1 to the statutory window).                             |
| `publicIntake`       | `false` | Accept `submitPublic` requests. Needs an email delivery callback.                                         |
| `exportLifetimeDays` | `14`    | How long an export stays downloadable (1 to 90 days).                                                     |

`null` clears `contactEmail`, `contactName` and `responseDays`. `getSettings` also returns the `statutory` windows
for display beside the tenant's own.

## Permissions

| Action               | Methods                                                                                                                                                                                          |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `iam:privacy:manage` | `createPurpose`, `updatePurpose`, `deletePurpose`, `placeHold`, `releaseHold`, `updateSettings`                                                                                                  |
| `iam:privacy:read`   | `listPurposes`, `listConsents`, `history`, `audience`, `verifyReceipt`, `listRequests`, `getRequest`, `listHolds`, `listRestrictions`, `getSettings`, `summary`                                  |
| `iam:privacy:record` | `record`, `importDecisions`                                                                                                                                                                      |
| `iam:privacy:check`  | `check`, `filterSubjects`                                                                                                                                                                        |
| `iam:privacy:handle` | `createRequest`, `verifyRequest`, `linkRequest`, `assignRequest`, `extendRequest`, `addNote`, `fulfilRequest`, `rejectRequest`, `liftRestriction`, and `downloadExport` of someone else's export |
| none (own session)   | `mine`, `decide`, `myHistory`, `myReceipt`, `submitRequest`, `cancelMyRequest`, `downloadExport` of one's own export                                                                             |
| none (public)        | `submitPublic`, `confirmPublic`                                                                                                                                                                  |

Actions are checked on the tenant (`iam/{tenantId}`), or on the record a call acts on: the purpose for
`updatePurpose` and `deletePurpose`, the request for `verifyRequest`, `linkRequest`, `assignRequest`,
`extendRequest`, `addNote`, `fulfilRequest`, `rejectRequest`, `getRequest` and a handler's `downloadExport`, and the
hold for `releaseHold`. Some calls also need a directory permission on the subject's account (`iam/{identityId}`):
`iam:identities:read` to fulfil access and portability requests, to download someone else's export and to link a
request to an account, and `iam:identities:delete` to fulfil an erasure. `audience` includes names and emails only
with `iam:identities:read`, and exports include audited activity only with `iam:audit:read`. A typical split gives the
privacy team `iam:privacy:manage`, `iam:privacy:read` and `iam:privacy:handle` (with the directory permissions),
support staff `iam:privacy:handle`, and application API keys `iam:privacy:record` and `iam:privacy:check`.

## Audit events

Every method that requires an `iam:privacy:*` action records it (outcome `allow` or `deny`) like any operation,
except that a handler's `downloadExport` records its refusals as `deny` and its successes only as
`privacy:export:download`; the self-service reads (`mine`, `myHistory`, `myReceipt`) are not audited. These events
record what happened:

| Event                             | Recorded when                                                                                                                  | Metadata                                                                                              |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------- |
| `privacy:consent`                 | A decision was recorded by `decide`, `record`, or `iam.privacy.record` (actor `application`)                                   | `purposeKey`, `granted`, `purposeVersion`, `source`, `receiptId`, `externalId` (application subjects) |
| `privacy:consent-import`          | `importDecisions` imported decisions                                                                                           | `count`, `current`, `purposes`                                                                        |
| `privacy:request:submit`          | A request was filed (actor `public-intake` for `submitPublic`)                                                                 | `number`, `type`, `regulation`, `channel`                                                             |
| `privacy:request:verify`          | `verifyRequest` or `confirmPublic` (actor `public-intake`) verified a request                                                  | `number`, `method`, `linked` (public intake)                                                          |
| `privacy:request:email-confirmed` | `confirmPublic` confirmed the address of a request naming an `externalId`, which still needs a handler (actor `public-intake`) | `number`                                                                                              |
| `privacy:request:link`            | `linkRequest` linked a request known by email to its subject                                                                   | `number`, `subjectKind` (`account` or `external`)                                                     |
| `privacy:request:cancel`          | The person withdrew their request                                                                                              | `number`, `type`                                                                                      |
| `privacy:request:extend`          | `extendRequest` moved the deadline                                                                                             | `number`, `dueAt`                                                                                     |
| `privacy:request:complete`        | `fulfilRequest` completed a request                                                                                            | `number`, `type`, `actions`                                                                           |
| `privacy:request:reject`          | `rejectRequest` refused a request                                                                                              | `number`, `type`, `reason`                                                                            |
| `privacy:request:due-soon`        | The deadline job found a request due soon (actor `deployment-operator`)                                                        | `number`, `type`, `dueAt`                                                                             |
| `privacy:request:overdue`         | The deadline job found a request overdue (actor `deployment-operator`)                                                         | `number`, `type`, `dueAt`                                                                             |
| `privacy:erasure`                 | An erasure request was fulfilled (resource: the account, or the subject key)                                                   | `requestId`, `subjectKind`, `externalId`                                                              |
| `privacy:export:download`         | An export was downloaded                                                                                                       | `number`, `by` (`subject` or `handler`)                                                               |
| `privacy:hold:place`              | A legal hold was placed                                                                                                        | `holdId`, `expiresAt` (when set)                                                                      |
| `privacy:hold:release`            | A legal hold was released                                                                                                      | `holdId`                                                                                              |
| `privacy:restriction:lift`        | A restriction of processing was lifted                                                                                         |                                                                                                       |

Consent and hold events name the account (or the subject key, such as `external:cus_100`) as their resource; request
events name the request. Decisions recorded while fulfilling an objection or opt-out are listed in the request's
`actions` rather than audited one by one, and an erasure that deletes an account also records `identity:delete` with
`erasure: true`. See [Events and webhooks](events.md#privacy-events).

## Scheduling

| Job                                   | How often       | Does                                                                            |
| ------------------------------------- | --------------- | ------------------------------------------------------------------------------- |
| `iam.privacy.sendDeadlineReminders()` | daily or hourly | Reminds handlers of requests due soon and overdue; lapses unconfirmed requests. |
| `iam.sweepExpired()`                  | hourly or daily | Deletes exports past their download window (with the other expired records).    |

## Email templates

Privacy emails are sent only when the deployment has an email delivery callback (`authentication.sendEmail`), and
emails to the privacy contact only when one is set. `renderDeliveryMessage` renders them:

| Template                   | To                                                        | When                                                                               |
| -------------------------- | --------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `privacy-request-verify`   | The requester's address                                   | A public request needs confirming.                                                 |
| `privacy-request-received` | The privacy contact                                       | A request opened (or a public request's address was confirmed) and needs handling. |
| `privacy-request-update`   | The subject (their account's address, or the requester's) | A request was extended, rejected or completed.                                     |
| `privacy-request-due`      | The assignee, or the privacy contact                      | A request is due soon or overdue.                                                  |

Give the templates a `links.privacy` builder. It receives `{ tenantId, requestId?, token?, handler?, signInUrl? }`
and returns: with `token`, the page that confirms a public request (it calls `privacy.confirmPublic`); with `handler`,
the request's page for whoever handles it; otherwise the person's own privacy page. Without a builder, the emails fall
back to `links.account`, and the confirmation email shows the request ID and code instead of a link.

```ts
import { renderDeliveryMessage } from 'better-iam/auth/templates';

sendEmail: async (message) => {
  const rendered = renderDeliveryMessage(message, {
    appName: 'Acme Cloud',
    links: {
      privacy: ({ tenantId, requestId, token, handler }) =>
        token
          ? `https://app.acme.test/privacy/confirm?tenant=${tenantId}&request=${requestId}&token=${token}`
          : handler
            ? `https://app.acme.test/admin/privacy/requests/${requestId}`
            : 'https://app.acme.test/account/privacy',
    },
  });
  if (rendered) await mailer.send({ to: message.to, ...rendered });
},
```

## Console

- **Home › Your privacy**: every purpose with its basis and status and a button to turn optional uses on or off (or
  object), the person's requests with withdraw and download buttons, a form to make a request, and the privacy
  contact.
- **Organization › Privacy**: request counts (open, overdue, due within seven days, awaiting verification, median days
  to close, legal holds), the request queue, forms to file a request for a member or for someone without an account,
  purposes with their consent counts (edit one, or publish a new version) and a new-purpose form, legal holds (place
  and release), restricted subjects (lift), and the settings. Each request has its own page to verify it, link it to an
  account or application subject, fulfil, assign, extend, add notes, reject, download the export, and read the
  timeline.
