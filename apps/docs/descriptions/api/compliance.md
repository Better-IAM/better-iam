# compliance

The compliance center: automated checks over the tenant's identity and access state (second factors, password and
session rules, inactive accounts, leavers who kept access, stale and long-lived API keys, access reviews, full
administrators, owners, separation of duties, audit chain integrity, data-subject request deadlines), mapped to
requirements of SOC 2, ISO/IEC 27001:2022, NIST SP 800-53 Rev. 5 and GDPR. A tenant turns checks into controls,
evaluates them daily and on demand, accepts findings with time-boxed exceptions that a second person approves, sees
each requirement's status, and exports evidence packs signed with an Ed25519 key that auditors verify offline. See the
[compliance guide](/docs/guides/governance/compliance); the repository guide is `docs/compliance.md`.

## Evidence, not coverage

Each mapping says a check is evidence for a requirement, not that it covers the requirement. SOC 2 CC6.1 or ISO 27001
8.5 also cover systems, processes and documents outside the identity system, so a passing requirement here passes only
for the part its checks measure, and an auditor still assesses the rest.

## Checks and statuses

A check returns findings (each with a `subject` and a `detail`: `identity:ID`, `session:ID` for an API key,
`trust:ID`, `role:ID`, `campaign:ID`, `request:ID`, or `tenant:ID:condition` for an organization-wide setting),
metrics, and a status: `pass`, `fail`, `warn` or `not-applicable`. The checks are `mfa-enforced`, `mfa-coverage`
(`minimumPercent`, 100), `password-length` (`minimum`, 12), `session-lifetime` (`maxHours`, 168, and `idleMinutes`,
1440), `inactive-accounts` (`days`, 90), `leaver-access`, `stale-api-keys` (`days`, 90), `api-key-lifetime`
(`maxDays`, 365), `access-reviews` (`intervalDays`, 90, `minDecidedPercent`, 80, and `minCoveragePercent`, 100),
`privileged-access` (`maxHolders`, 5), `owner-redundancy`, `separation-of-duties`, `audit-integrity` (verified
incrementally from a stored checkpoint; its findings cannot be excepted) and `privacy-deadlines`;
[`catalog`](#catalog) returns each with its parameters' ranges. A check that cannot run fails its control. An approved,
unexpired exception removes one finding from its control's status; `rawStatus` keeps what the check found.

Stored results identify people only by ID. When results are read (`listResults`, `listControls`, `exportEvidence`),
findings about people carry `name` (the email address or name) for callers allowed `iam:identities:read` on the
tenant, and results more than three days old carry `stale: true`.

## Permissions

`iam:compliance:read` covers `catalog`, `listControls`, `status`, `listRuns`, `listResults`, `listExceptions`,
`exportEvidence`, `evidenceKeys` and `verifyEvidence`; `iam:compliance:evaluate` covers `evaluate`;
`iam:compliance:manage` covers `adoptFramework`, the control methods, `createException`, `approveException` and
`revokeException`. Actions are checked on `iam/TENANT_ID`, or on the control (`updateControl`, `deleteControl`) or
exception (`approveException`, `revokeException`) a call acts on. Evaluations read the whole directory whoever
triggers them, so results show findings about people the caller may not otherwise read (by ID, unless the caller may
read the directory). Results and runs are kept 400 days, and exceptions 400 days after they expire, then
`iam.sweepExpired()` removes them; the scheduler job `iam.compliance.evaluateAll()` (or the CLI command
`compliance-evaluate`) evaluates every tenant daily.

## adoptFramework

Adopts a framework: one control per check its requirements use, mapped to those requirements.

- **Permission:** `iam:compliance:manage` on the tenant.
- **Audited as:** `iam:compliance:manage`, plus `compliance:framework:adopt` with the framework and the control keys.
- **Errors:** `INVALID_INPUT` for a framework other than `soc2`, `iso27001`, `nist-800-53` or `gdpr`;
  `LIMIT_EXCEEDED` (409) past 200 controls.

Each new control is keyed by the check's id, named and described like the check, uses its default parameters, and is
mapped as `framework:requirement` (`soc2:CC6.1`). A control already running that check (the one keyed by the check's
id, else the first by key) gains the framework's mappings instead, so frameworks share controls. The result is
`framework` and the `controls` created or extended.

## approveException

Approves a pending exception, so it covers its finding from the next evaluation until it expires.

- **Permission:** `iam:compliance:manage` on the exception.
- **Audited as:** `iam:compliance:manage`, plus `compliance:exception:approve` with the control key, subject, author
  and expiry.
- **Errors:** `ACCESS_DENIED` (403) when the caller proposed the exception or is the subject of its finding;
  `CONFLICT` (409) when the exception is not pending or has expired; `NOT_FOUND` when it is not in this tenant.

The approver must be a second person: exceptions take two holders of `iam:compliance:manage`. The result is the
exception with `status: 'approved'`, `approvedBy` and `approvedAt`.

```ts
await iam.api.compliance.approveException(credential, { tenantId, exceptionId });
```

```ts
await iam.api.compliance.adoptFramework(admin, { tenantId, framework: 'iso27001' });
```

## catalog

Returns the built-in checks with their parameters, and the framework mappings.

- **Permission:** `iam:compliance:read` on the tenant.
- **Audited as:** `iam:compliance:read`.

`checks` lists each check's `id`, `title`, `description` and `params` (`name`, `description`, `default`, `min`,
`max`), and `noExceptions: true` for a check whose findings cannot be excepted (`audit-integrity`). `frameworks` lists each framework's `id`, `name` and `requirements` (`id`, `title`, and the `checks` that
evidence it). The same data is exported as `complianceChecks` and `complianceFrameworks` from `@better-iam/server`.

## createControl

Adds a control that runs one check with parameters and mappings of your own.

- **Permission:** `iam:compliance:manage` on the tenant.
- **Audited as:** `iam:compliance:manage`, plus `compliance:control:create` with the key, check and settings.
- **Errors:** `INVALID_INPUT` for a malformed key, an unknown check, a name over 120 characters or a description over
  1000, an unknown parameter or a value outside its range, more than 50 mappings or one over 64 characters, or a
  non-boolean `enabled`; `CONFLICT` (409) when a control has the key; `LIMIT_EXCEEDED` (409) past 200 controls.

`key` is permanent (1 to 64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter).
Parameters left out take their defaults. A mapping in the form `framework:requirement` counts toward
[`status`](#status); other text, such as an internal policy number, is kept for your records and the evidence.

```ts
await iam.api.compliance.createControl(admin, {
  tenantId,
  key: 'inactive-30',
  name: 'Accounts unused for 30 days are reviewed',
  checkId: 'inactive-accounts',
  params: { days: 30 },
  mappings: ['internal:POL-7', 'soc2:CC6.2'],
});
```

## createException

Proposes accepting one finding of a control until a date; once a second person approves it, the finding no longer
counts toward the control's status.

- **Permission:** `iam:compliance:manage` on the tenant.
- **Audited as:** `iam:compliance:manage`, plus `compliance:exception` with the control key, subject, expiry and
  `status: 'pending'`.
- **Errors:** `NOT_FOUND` when the tenant has no control with `controlKey`; `INVALID_INPUT` for an `expiresAt` less
  than a minute or more than 366 days away, a subject over 300 characters, a reason over 1000, or a control whose
  check's findings cannot be excepted (`audit-integrity`); `ACCESS_DENIED` (403) for a finding about the caller
  (`identity:` followed by their own ID).

`subject` is the finding's subject as the result names it (`identity:ID`, `session:ID`, `tenant:ID:mfa-optional`,
...). The exception starts `pending` and covers nothing until someone else approves it with
[`approveException`](#approveexception); from the next evaluation after that, the finding is marked `excepted` and the
control is judged on the rest. There are no permanent exceptions.

```ts
await iam.api.compliance.createException(admin, {
  tenantId,
  controlKey: 'inactive-30',
  subject: `identity:${identityId}`,
  reason: 'On parental leave until December',
  expiresAt: Date.parse('2026-12-31T00:00:00Z'),
});
```

## deleteControl

Deletes a control and revokes its exceptions.

- **Permission:** `iam:compliance:manage` on the control.
- **Audited as:** `iam:compliance:manage`, plus `compliance:control:delete` with the key, check and settings.
- **Errors:** `NOT_FOUND` when the control is not in this tenant.

Its exceptions stay as revoked history, and its past results stay until they expire, 400 days after their evaluation. To stop evaluating a control but keep it,
set `enabled: false` with [`updateControl`](#updatecontrol).

## evaluate

Runs the tenant's enabled controls now, or the ones named in `controlKeys`.

- **Permission:** `iam:compliance:evaluate` on the tenant.
- **Audited as:** `iam:compliance:evaluate`, plus `compliance:evaluate` with the counts and digest, and
  `compliance:control:fail` or `compliance:control:recover` for each control that started or stopped failing.
- **Errors:** `INVALID_INPUT` for more than 100 `controlKeys`; `RATE_LIMITED` (429) within a minute of the tenant's
  last evaluation, scheduled ones included.

The checks read outside any transaction, so an evaluation never holds the store's write lock while it walks a large
tenant; the results, the run and their audit events are then written in one short transaction, leaving out a control
deleted or changed meanwhile. The result is the `run` (`counts` per status and a `digest`, the SHA-256 of the results'
canonical JSON, also recorded in the audit chain) and the `results`: per control its `controlKey`, `checkId`,
`status`, `rawStatus` (before exceptions), `summary`, `findingsTotal` and `excepted`. The stored results also keep the
`metrics` and up to 200 `findings`; read them with [`listResults`](#listresults). Disabled controls and unknown keys are
skipped.

```ts
const { run, results } = await iam.api.compliance.evaluate(admin, { tenantId });
const failing = results.filter((result) => result.status === 'fail');
```

## evidenceKeys

Returns the public keys evidence packs are signed with, as a JWKS, for auditors' offline checks.

- **Permission:** `iam:compliance:read` on the tenant.
- **Audited as:** `iam:compliance:read`.

The result is `{ keys }`, each `{ kty: 'OKP', crv: 'Ed25519', x, kid, alg: 'EdDSA', use: 'sig' }`: first the key
derived from the deployment `secret`, then one per entry of `previousSecrets`. `kid` is the key's RFC 7638
thumbprint. Hand the keys to auditors with the pack; `verifyEvidencePack(pack, jwks)` from `@better-iam/server` checks
a pack with them, without a server.

```ts
import { verifyEvidencePack } from '@better-iam/server';

const jwks = await iam.api.compliance.evidenceKeys(credential, { tenantId });
const { valid, reason } = verifyEvidencePack(pack, jwks);
```

## exportEvidence

Returns a signed evidence pack for auditors: the controls, their latest results, exceptions and recent runs.

- **Permission:** `iam:compliance:read` on the tenant.
- **Audited as:** `iam:compliance:read`, plus `compliance:evidence-export` with the framework, the number of controls,
  the pack's digest and the signing key's id.
- **Errors:** `INVALID_INPUT` for an unknown framework.

The pack (`format: 'better-iam.compliance-evidence'`, `version: 2`) holds the controls (only those mapped to
`framework` when given; disabled ones with `enabled: false`) with their parameters, mappings and latest result and
findings (marked `stale` past three days), every exception of those controls with its `status` and approval and
revocation history, the 30 latest runs with their digests, and the tenant's audit chain head (`auditHead`). `digest`
is the SHA-256 (base64url) of its canonical JSON without `digest` and `signature`, and `signature`
(`{ alg: 'EdDSA', kid, value }`) an Ed25519 signature over the digest by a key derived from the deployment secret,
published by [`evidenceKeys`](#evidencekeys) and checked by [`verifyEvidence`](#verifyevidence). Findings name people
by ID, and by email address or name when the caller may read the directory, so treat packs as personal data.

## listControls

Lists the tenant's controls by name, each with its latest result.

- **Permission:** `iam:compliance:read` on the tenant.
- **Audited as:** `iam:compliance:read`.

Each control carries `key`, `name`, `description`, `checkId`, `params`, `mappings`, `enabled`, `lastStatus`,
`lastEvaluatedAt`, and `latest`, the result of its most recent evaluation, with findings (people's names for callers
who may read the directory) and `stale` (older than three days).

## listExceptions

Lists the tenant's exceptions by expiry, pending, revoked and expired ones included.

- **Permission:** `iam:compliance:read` on the tenant.
- **Audited as:** `iam:compliance:read`.

Each exception carries `controlKey`, `subject`, `reason`, `expiresAt`, `createdBy`, `createdAt`, `status`
(`pending`, `approved` or `revoked`; exceptions made before approvals existed count as `approved`), `approvedBy` and
`approvedAt` or `revokedBy` and `revokedAt` when set, and `active` (approved and not expired: it covers its finding
now). Records are kept until 400 days after they expire.

## listResults

Returns results: the latest of every control, or a control's history, or one run's results.

- **Permission:** `iam:compliance:read` on the tenant.
- **Audited as:** `iam:compliance:read`.
- **Errors:** `INVALID_INPUT` for a `limit` outside 1 to 1000.

Without `controlKey` or `runId`, the result is the latest result of each control, by key. With either or both, it is
the matching results, newest first, at most `limit` (100 by default).

## listRuns

Lists evaluation runs, newest first.

- **Permission:** `iam:compliance:read` on the tenant.
- **Audited as:** `iam:compliance:read`.
- **Errors:** `INVALID_INPUT` for a `limit` outside 1 to 500.

Each run carries `evaluatedAt`, `counts` per status, `digest`, and `triggeredBy` (the caller's id, or
`deployment-operator` for the scheduler job). `limit` is 30 by default.

## revokeException

Ends an exception, or withdraws a pending one, so its finding counts again from the next evaluation.

- **Permission:** `iam:compliance:manage` on the exception.
- **Audited as:** `iam:compliance:manage`, plus `compliance:exception:revoke` with the control key and subject.
- **Errors:** `NOT_FOUND` when the exception is not in this tenant.

The record stays as history, with `status: 'revoked'`, `revokedBy` and `revokedAt`, in
[`listExceptions`](#listexceptions) and evidence packs. Revoking an exception that is already revoked changes nothing.
The result is `{ revoked: true }`.

## status

Returns each framework requirement with the controls that evidence it and their latest status.

- **Permission:** `iam:compliance:read` on the tenant.
- **Audited as:** `iam:compliance:read`.
- **Errors:** `INVALID_INPUT` for an unknown `framework`.

Without `framework`, the result covers every framework a control is mapped to. A requirement's status is `no-control`
without any mapped control, and otherwise the worst of its controls, from worst to best: `fail`, `disabled` (a mapped
control is disabled), `not-evaluated` (a mapped control has no result, or only a stale one older than three days),
`warn`, `pass`, `not-applicable`. Each control is listed with `key`, `name`, `enabled`, and its latest `status`,
`evaluatedAt` and `stale`. `total` counts the framework's requirements, `covered` those with a control (enabled or
not), and `passing` those that pass or are not applicable.

```ts
const [soc2] = await iam.api.compliance.status(admin, { tenantId, framework: 'soc2' });
const open = soc2.requirements.filter((requirement) => requirement.status === 'fail');
```

## updateControl

Changes a control's name, description, parameters, mappings, or whether it is evaluated.

- **Permission:** `iam:compliance:manage` on the control.
- **Audited as:** `iam:compliance:manage`, plus `compliance:control:update` with the settings before and after.
- **Errors:** `INVALID_INPUT` as for [`createControl`](#createcontrol); `NOT_FOUND` when the control is not in this
  tenant.

Fields you leave out keep their values; `params` and `mappings` replace the whole set. The key and the check cannot
change. New parameters apply from the next evaluation.

## verifyEvidence

Tells whether an evidence pack is unaltered and was signed by this deployment.

- **Permission:** `iam:compliance:read` on the tenant.
- **Audited as:** `iam:compliance:read`.
- **Errors:** `INVALID_INPUT` without a `pack`, or without a `digest` and `signature` in its place.

The result is `{ valid: true }` when the pack belongs to this tenant, its digest matches its content, and its signature
verifies with the evidence key of the deployment `secret` or of one of `previousSecrets`, and `{ valid: false }` for
a pack that was edited, belongs to another tenant, or has no signature. For a pack too large to send, pass only its
`digest` and `signature`: then only the signature is checked, so recompute the digest and check the tenant yourself.
Version 1 packs, signed with HMAC-SHA256 before evidence keys existed, still verify here. Auditors without access to
the deployment use `verifyEvidencePack` with the keys from [`evidenceKeys`](#evidencekeys) instead.

```ts
const { valid } = await iam.api.compliance.verifyEvidence(admin, { tenantId, pack });
```
