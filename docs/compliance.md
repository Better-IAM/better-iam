# Compliance center

The compliance center checks an organization's identity and access state against the controls auditors ask about:
whether people must use a second factor and have one, whether sessions and API keys end, whether leavers lose their
access, whether access is reviewed, how many people hold full administration, whether separation of duties holds,
whether the audit log is intact, and whether data-subject requests are answered on time. Each check is mapped to
requirements of SOC 2, ISO/IEC 27001:2022, NIST SP 800-53 Rev. 5 and GDPR.

A tenant turns checks into **controls**, evaluates them (daily, and on demand), accepts individual findings with
time-boxed **exceptions** that a second person approves, sees each framework requirement's status, and exports signed
**evidence packs** its auditors can verify offline. Everything lives in the `compliance` API group
(`POST /api/iam/compliance/{method}`, `client.compliance.*` in the browser), and the deployment evaluates every
organization with `iam.compliance.evaluateAll()`.

The mappings are evidence for those requirements, not full coverage of them. A requirement such as SOC 2 CC6.1 or ISO
27001 control 8.5 also covers systems, processes and documents Better IAM never sees, so a passing control shows that
this part of the requirement holds in the identity system, and an auditor still assesses the rest. Passing every
control does not make an organization compliant.

```ts
// Adopt SOC 2: one control per check its requirements use.
await iam.api.compliance.adoptFramework(admin, { tenantId, framework: 'soc2' });

// Evaluate now (the daily job does this too).
const { run, results } = await iam.api.compliance.evaluate(admin, { tenantId });

// Each requirement with the status of the controls that evidence it.
const [soc2] = await iam.api.compliance.status(admin, { tenantId, framework: 'soc2' });

// A signed evidence pack for the auditor, and the public keys that verify it.
const pack = await iam.api.compliance.exportEvidence(admin, { tenantId, framework: 'soc2' });
const jwks = await iam.api.compliance.evidenceKeys(admin, { tenantId });
```

## Checks

Every check reads the tenant's current state and returns findings (what needs attention, each with a `subject` and a
`detail`), metrics, and a status: `pass`, `fail`, `warn` or `not-applicable`.

| Check                  | What it measures                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Parameters (default, range)                                                                               | Status                                                                                       | Evidence for                                           |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| `mfa-enforced`         | Whether the organization's sign-in policy requires a second factor for everyone (`authPolicy.requireMfa`).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | none                                                                                                      | `pass` when required; `warn` when only owners must (`requireMfaForOwners`); `fail` otherwise | SOC 2 CC6.1; ISO 27001 8.5; NIST IA-2(1)               |
| `mfa-coverage`         | The share of active people with an authenticator app enrolled, or a passkey when the deployment enables passkeys (`authentication.passkeys`); each person without one is a finding.                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | `minimumPercent` (100, 50 to 100)                                                                         | `fail` below the share                                                                       | SOC 2 CC6.1; ISO 27001 8.5; NIST IA-2(1); GDPR Art. 32 |
| `password-length`      | The minimum password length the organization enforces (its `minPasswordLength`, never below 12), or whether passwords are not an allowed sign-in method at all.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | `minimum` (12, 8 to 64)                                                                                   | `fail` when shorter; `pass` without passwords                                                | SOC 2 CC6.1; ISO 27001 5.17; NIST IA-5                 |
| `session-lifetime`     | The longest session and the longest idle time before sign-out: the deployment's `authentication.sessionLifetimeMs` and `sessionIdleTimeoutMs` (7 days and 24 hours by default), shortened by the organization's policy.                                                                                                                                                                                                                                                                                                                                                                                                                                      | `maxHours` (168, 1 to 720); `idleMinutes` (1440, 5 to 10080)                                              | `fail` when either is longer                                                                 | SOC 2 CC6.1; ISO 27001 8.5; NIST AC-12                 |
| `inactive-accounts`    | Active people who have not signed in for `days` (or never have), leaving out accounts created within that time.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | `days` (90, 7 to 730)                                                                                     | `fail` per person                                                                            | SOC 2 CC6.2; ISO 27001 5.16; NIST AC-2                 |
| `leaver-access`        | Disabled or expired accounts (people, service accounts and agents) that still hold live sessions or API keys, direct role bindings, or group memberships.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | none                                                                                                      | `fail` per account                                                                           | SOC 2 CC6.2; ISO 27001 5.16; NIST AC-2; GDPR Art. 32   |
| `stale-api-keys`       | Live API keys not used for `days` (counted from creation when never used).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | `days` (90, 7 to 730)                                                                                     | `fail` per key                                                                               | SOC 2 CC6.3; ISO 27001 5.18; NIST IA-5                 |
| `api-key-lifetime`     | Live API keys whose lifetime, from creation to expiry, is longer than `maxDays`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | `maxDays` (365, 1 to 3650)                                                                                | `fail` per key                                                                               | SOC 2 CC6.1; ISO 27001 5.17; NIST IA-5                 |
| `access-reviews`       | Whether a certification campaign that counts closed within `intervalDays`: one with items, at least `minDecidedPercent` of them decided by a reviewer. Counted campaigns must have covered `minCoveragePercent` of the roles held today (live bindings to unprotected roles); each uncovered role and each open campaign past its due date is a finding.                                                                                                                                                                                                                                                                                                     | `intervalDays` (90, 7 to 730); `minDecidedPercent` (80, 50 to 100); `minCoveragePercent` (100, 50 to 100) | `fail` without a counted review, below the coverage, or with an overdue campaign             | SOC 2 CC6.3; ISO 27001 5.18; NIST AC-6(7)              |
| `privileged-access`    | Everyone who can administer the organization, by any path: owners and root administrators; active holders (directly or through a group) of a live binding to a role that, itself or through a role it inherits, allows `iam:bindings:create`, `iam:roles:update` and `iam:policies:update` on the tenant in one statement (conditions are ignored: they change when someone may act, not who holds the power); eligible bindings to such a role while activated, or when activation needs no approval; and trusts that assume such a role. Every holder is a finding; eligible bindings that need approval are counted in the `eligibleWithApproval` metric. | `maxHolders` (5, 1 to 1000)                                                                               | `fail` above the maximum                                                                     | SOC 2 CC6.3; ISO 27001 8.2; NIST AC-6                  |
| `owner-redundancy`     | Whether the organization has at least two active owners, so losing one account does not lock it out.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | none                                                                                                      | `warn` with one; `fail` with none                                                            | ISO 27001 8.2                                          |
| `separation-of-duties` | People who hold two roles a [separation-of-duties](policies.md#separation-of-duties) rule keeps apart.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | none                                                                                                      | `warn` without rules; `fail` per violation                                                   | SOC 2 CC6.3; ISO 27001 5.3; NIST AC-5                  |
| `audit-integrity`      | Whether the tenant's audit hash chain verifies up to its head: no event changed, removed or inserted. Each evaluation continues from the checkpoint the last one stored (up to 100,000 events per run) and compares the newest event with the chain head; a pruned prefix must match its `audit:prune` record. Its findings cannot be excepted.                                                                                                                                                                                                                                                                                                              | none                                                                                                      | `fail` when the chain breaks; `warn` while verification has not reached the head yet         | SOC 2 CC7.2; ISO 27001 8.15; NIST AU-9; GDPR Art. 32   |
| `privacy-deadlines`    | Open [data-subject requests](privacy.md#data-subject-requests) past their statutory deadline.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | none                                                                                                      | `fail` per request                                                                           | ISO 27001 5.34; GDPR Art. 12                           |

Findings name their subject as `identity:{id}` (`identity:{id}:rule:{ruleId}` for a separation-of-duties violation),
`session:{id}` (an API key), `trust:{id}`, `role:{id}`, `campaign:{id}`, `request:{id}`, or `tenant:{id}:{condition}`
for an organization-wide setting, such as `tenant:{id}:mfa-optional` or `tenant:{id}:idle-1440m`. A subject that
carries a setting's value stops matching its exception when the value changes. A finding's `detail` is plain text
without names: stored results identify people only by ID, and [names are added when results are read](#evaluating).
Metrics carry the numbers behind the status, such as `people` and `enrolled` for `mfa-coverage`, `holders` for
`privileged-access`, or `verifiedThrough` for `audit-integrity`. The checks and their parameters are exported as
`complianceChecks` from `@better-iam/server`, and `catalog` returns them with the frameworks (`noExceptions: true`
marks `audit-integrity`).

## Frameworks

| Framework     | Name                            | Requirements and the checks that evidence them                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ------------- | ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `soc2`        | SOC 2 (Trust Services Criteria) | CC6.1 Logical access security: `mfa-enforced`, `mfa-coverage`, `password-length`, `session-lifetime`, `api-key-lifetime`. CC6.2 Registration and deregistration of users: `leaver-access`, `inactive-accounts`. CC6.3 Role-based access, least privilege, and access review: `access-reviews`, `privileged-access`, `separation-of-duties`, `stale-api-keys`. CC7.2 Monitoring of system components: `audit-integrity`.                                                                            |
| `iso27001`    | ISO/IEC 27001:2022 Annex A      | 5.3 Segregation of duties: `separation-of-duties`. 5.16 Identity management: `leaver-access`, `inactive-accounts`. 5.17 Authentication information: `password-length`, `api-key-lifetime`. 5.18 Access rights: `access-reviews`, `stale-api-keys`. 5.34 Privacy and protection of PII: `privacy-deadlines`. 8.2 Privileged access rights: `privileged-access`, `owner-redundancy`. 8.5 Secure authentication: `mfa-enforced`, `mfa-coverage`, `session-lifetime`. 8.15 Logging: `audit-integrity`. |
| `nist-800-53` | NIST SP 800-53 Rev. 5           | AC-2 Account management: `leaver-access`, `inactive-accounts`. AC-5 Separation of duties: `separation-of-duties`. AC-6 Least privilege: `privileged-access`. AC-6(7) Review of user privileges: `access-reviews`. AC-12 Session termination: `session-lifetime`. IA-2(1) Multi-factor authentication: `mfa-enforced`, `mfa-coverage`. IA-5 Authenticator management: `password-length`, `api-key-lifetime`, `stale-api-keys`. AU-9 Protection of audit information: `audit-integrity`.             |
| `gdpr`        | GDPR (selected articles)        | Art. 12 Responding to data subjects in time: `privacy-deadlines`. Art. 32 Security of processing: `mfa-coverage`, `audit-integrity`, `leaver-access`.                                                                                                                                                                                                                                                                                                                                              |

The table is exported as `complianceFrameworks` from `@better-iam/server`. Again: each mapping says the check is
evidence for the requirement, not that it covers all of it.

## Controls

A control is a check as the tenant runs it: a `key`, a `name`, the `checkId`, its `params`, and the requirements it
evidences (`mappings`). A tenant holds at most 200 controls.

**Adopting a framework** creates one control per check its requirements use, with the check's title, description and
default parameters, keyed by the check's id, and mapped to the requirements as `framework:requirement` (`soc2:CC6.1`).
A control already running that check (the one keyed by the check's id, else the first by key) gains the framework's
mappings instead, so adopting ISO 27001 after SOC 2 reuses the same `mfa-coverage` control with both `soc2:CC6.1` and
`iso27001:8.5`. `adoptFramework` returns the framework and the controls it created or extended, and is audited as
`compliance:framework:adopt`.

**Custom controls** run a check with parameters of your own, and map it to any references you like, such as an
internal policy number:

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

- `key` is permanent: 1 to 64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter, unique
  in the tenant. `name` is up to 120 characters and `description` up to 1000.
- `params` names only the check's parameters, as integers within their ranges; the ones left out take their defaults.
  An unknown parameter or a value out of range answers `INVALID_INPUT`. A stored value outside a range that a later
  release tightened is brought within it when the control is evaluated.
- `mappings` holds up to 50 references of up to 64 characters. A reference in the form `framework:requirement` for a
  built-in framework makes the control count toward that requirement's [status](#framework-status); any other text
  is kept as a label for your own records and the evidence.
- `enabled` (true by default): disabled controls are not evaluated, a requirement mapped to one shows `disabled`
  rather than passing, and evidence packs list them with `enabled: false`.

`updateControl` changes the name, description, parameters, mappings or `enabled`; the key and check stay.
`deleteControl` removes a control and revokes its exceptions (they stay as history); its past results stay until they
expire. These are audited as `compliance:control:create`, `compliance:control:update` (with the state before and
after) and `compliance:control:delete`. `listControls` lists the controls by name, each with its `latest` result.

## Evaluating

`evaluate` (`iam:compliance:evaluate`) runs every enabled control of the tenant, or only the enabled ones named in
`controlKeys` (up to 100 keys), at most once a minute per tenant: within a minute of the last evaluation (scheduled
ones included) it answers `RATE_LIMITED`. The checks read outside any transaction, so an evaluation never holds the
store's write lock while it walks a large tenant, and they do not see one consistent snapshot. The results, the run
and their audit events are then written in one short transaction; a control deleted or changed while the checks ran is
left out. The scheduler job `iam.compliance.evaluateAll()` does the same for every active tenant with enabled
controls, without the one-minute limit ([scheduling](#scheduling)).

`evaluate` returns the `run` and, for each control, its `controlKey`, `checkId`, `status`, `rawStatus`, `summary`,
`findingsTotal` and `excepted`; read the findings with `listResults` (`iam:compliance:read`). Each stored result
carries:

- `status`, and `rawStatus`, the status before exceptions were applied;
- `summary`, a sentence such as "82% of people have a second factor (at least 100% required)";
- `metrics`;
- `findings`, at most 200 of them, the ones an exception covers marked `excepted: true`, with `findingsTotal` and
  `excepted` counting all of them;
- `runId`, `controlKey`, `checkId` and `evaluatedAt`.

A check that cannot run (an error while reading the state) fails its control, with the reason in the summary, rather
than passing by omission. Each control also records `lastStatus` and `lastEvaluatedAt`.

Results as they are read back (`listResults`, `listControls`, evidence packs) also carry:

- `stale: true` when they are more than three days old: the scheduled evaluation has not run, or has failed, since;
- on each finding about a person, `name` (the email address, or the name) for callers who may read the directory
  (`iam:identities:read` on the tenant). Others see only the ID in the subject.

The run records `counts` per status and a `digest`: the SHA-256 of the canonical JSON of every result's control key,
status, finding and exception counts, and metrics. The digest is written to the audit log with the
`compliance:evaluate` event, so the tamper-evident audit chain vouches for what each evaluation found. When a control
starts failing, or stops failing, compared with its previous evaluation, the run also records
`compliance:control:fail` or `compliance:control:recover`; subscribe a webhook to them to hear about regressions.

`listRuns` lists runs newest first (`limit`, 30 by default, up to 500). `listResults` returns the latest result of
every control, or, given a `controlKey` and/or a `runId`, the matching results newest first (`limit`, 100 by default,
up to 1000): a control's history, or everything one run found.

## Exceptions

An exception accepts one finding of one control for a while: a compensating control, a planned fix, a person on
leave. One person proposes it and a second approves it; from then until it expires, the finding no longer counts
toward its control's status.

```ts
const exception = await iam.api.compliance.createException(admin, {
  tenantId,
  controlKey: 'inactive-30',
  subject: `identity:${aliceId}`,
  reason: 'On parental leave until December',
  expiresAt: Date.parse('2026-12-31T00:00:00Z'),
});

// Someone else with iam:compliance:manage approves it.
await iam.api.compliance.approveException(otherAdmin, { tenantId, exceptionId: exception.id });
```

- `subject` is the finding's subject exactly as the result names it (`identity:{id}`, `session:{id}`,
  `tenant:{id}:mfa-optional`, ...), up to 300 characters, and `reason` up to 1000.
- `expiresAt` must be at least a minute and at most 366 days away. There is no permanent exception: renew it, or fix
  the finding.
- `createException` records the exception as `pending`, and it covers nothing until `approveException` approves it.
  The approver needs `iam:compliance:manage` and cannot be the author. Nobody may propose or approve an exception for a
  finding about themselves (`identity:{their id}`, or a subject that starts with it), `audit-integrity` findings cannot
  be excepted, and an exception that expired while pending can no longer be approved.
- The next evaluation applies an approved exception: the finding is marked `excepted`, `status` is judged on the rest,
  and `rawStatus` keeps what the check found. With `privileged-access`, an excepted holder no longer counts toward
  `maxHolders`; with `mfa-coverage`, an excepted person counts as enrolled.
- `revokeException` ends an approved exception or withdraws a pending one. The record stays as history, with
  `status: 'revoked'`, `revokedBy` and `revokedAt`; deleting a control revokes its exceptions the same way.
- `listExceptions` lists every exception by expiry with its `status` (`pending`, `approved` or `revoked`) and `active`
  (approved and not expired). Exceptions created before approvals existed count as approved.
- Proposals, approvals and revocations are recorded as `compliance:exception`, `compliance:exception:approve` and
  `compliance:exception:revoke`, and evidence packs carry every exception of their controls with its history.

## Framework status

`status` (`iam:compliance:read`) returns, for one `framework` or for every framework a control is mapped to, each
requirement with the controls mapped to it (`key`, `name`, `enabled`, and their latest result's `status`,
`evaluatedAt` and `stale`) and a status:

- `no-control`: no control is mapped to the requirement;
- otherwise the worst of its controls, from worst to best: `fail`; `disabled` (a mapped control is disabled);
  `not-evaluated` (a mapped control has no result yet, or only a stale one); `warn`; `pass`; `not-applicable`.

So a disabled, stale or never-evaluated control keeps its requirement from passing. `total` counts the framework's
requirements, `covered` those with at least one control (enabled or not), and `passing` those of them that pass (or
are not applicable). An unknown `framework` answers `INVALID_INPUT`. A requirement that passes here passes only for the
part its checks measure.

## Evidence packs

`exportEvidence` (`iam:compliance:read`) returns a JSON evidence pack for auditors:

```json
{
  "format": "better-iam.compliance-evidence",
  "version": 2,
  "generatedAt": "2026-09-24T08:00:00.000Z",
  "tenant": { "id": "…", "name": "Acme" },
  "framework": { "id": "soc2", "name": "SOC 2 (Trust Services Criteria)" },
  "controls": [
    {
      "key": "mfa-coverage",
      "name": "People have a second factor",
      "checkId": "mfa-coverage",
      "params": { "minimumPercent": 100 },
      "mappings": ["soc2:CC6.1"],
      "enabled": true,
      "result": {
        "runId": "…",
        "status": "pass",
        "rawStatus": "pass",
        "summary": "100% of people have a second factor",
        "metrics": { "people": 42, "enrolled": 42 },
        "findings": [],
        "findingsTotal": 0,
        "excepted": 0,
        "evaluatedAt": 1790000000000,
        "stale": false
      }
    }
  ],
  "exceptions": [],
  "runs": [
    {
      "id": "…",
      "evaluatedAt": 1790000000000,
      "counts": { "pass": 11, "fail": 1, "warn": 1, "not-applicable": 0 },
      "digest": "…"
    }
  ],
  "auditHead": { "sequence": 4812, "hash": "…" },
  "digest": "…",
  "signature": { "alg": "EdDSA", "kid": "…", "value": "…" }
}
```

- `controls` holds the tenant's controls (only those mapped to `framework` when one is given), disabled ones included
  with `enabled: false`, each with its latest result and findings (`stale` when more than three days old); `exceptions`
  every exception of those controls with its `status` (`pending`, `approved` or `revoked`) and who proposed, approved
  and revoked it, and when; `runs` the 30 latest runs with their digests; and `auditHead` the tenant's audit chain head
  at export time, which covers the `compliance:evaluate` events carrying those digests.
- `digest` is the SHA-256 (base64url) of the pack's canonical JSON (keys sorted) without `digest` and `signature`.
  `signature.value` is an Ed25519 signature over that digest string, by the key `signature.kid` names, derived from the
  deployment `secret` so every instance signs alike. The export's `compliance:evidence-export` audit event records the
  digest and key id, so the audit chain vouches for the pack as it was handed out.
- `evidenceKeys` (`iam:compliance:read`) returns the public keys as a JWKS,
  `{ keys: [{ kty: 'OKP', crv: 'Ed25519', x, kid, alg: 'EdDSA', use: 'sig' }] }`: the current `secret`'s key first, then
  one per `previousSecrets` entry. `kid` is the key's RFC 7638 thumbprint.
- `verifyEvidencePack(pack, jwks)` from `@better-iam/server` verifies a pack offline, without a server: the digest must
  match the pack's content and the signature must verify with the key it names. It returns `{ valid, kid?, reason? }`,
  the reason being `unsigned`, `digest mismatch`, `unknown key` or `bad signature`. Hand auditors the JWKS with the
  pack: it keeps verifying after the secret is rotated out.
- `verifyEvidence` (`iam:compliance:read`) checks on the server. It answers `{ valid: true }` for an unaltered pack of
  the same tenant, signed with the key of the current `secret` or of one in `previousSecrets`, and `{ valid: false }`
  for an edited pack, one from another tenant, or one without a signature. For a pack too large to send, pass only its
  `digest` and `signature`: then only the signature is checked, so recompute the digest and check the tenant yourself.
  Version 1 packs, signed with HMAC-SHA256 before evidence keys existed, still verify here (but not offline).

```ts
import { verifyEvidencePack } from '@better-iam/server';

const { valid, reason } = verifyEvidencePack(pack, jwks); // jwks from evidenceKeys
```

Each export is audited as `compliance:evidence-export` with the framework, the number of controls, the digest and the
key id. Findings name people by ID, and by email address or name when the exporting caller may read the directory, so
handle packs like any other export of personal data.

## Scheduling

| Job                            | How often | Does                                                                                                                               |
| ------------------------------ | --------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `iam.compliance.evaluateAll()` | daily     | Evaluates every active tenant with enabled controls, one after another.                                                            |
| `iam.sweepExpired()`           | daily     | Deletes results and runs 400 days after their evaluation, and exceptions 400 days after they expired (with other expired records). |

`evaluateAll({ tenantId? })` returns `{ evaluated, failed }`: `evaluated` lists `{ tenantId, runId, counts }` per
tenant, and its evaluations are audited with actor `deployment-operator`. A tenant whose evaluation fails is listed in
`failed` with its error's `code` and `message`, without stopping the others; its controls keep their last results,
which show as stale after three days. The console runs it once a day. To run it from a scheduler without code of your own, use the CLI, which loads
the deployment from your configuration file and needs no credential:

```bash
better-iam compliance-evaluate                    # every active tenant
better-iam compliance-evaluate --tenant ten_123   # one tenant
```

## Retention

Results and runs are kept 400 days (`expiresAt`), a year of history for an audit period plus a margin, then
`iam.sweepExpired()` deletes them. Exceptions, revoked ones included, are deleted 400 days after they expired, so
evidence packs keep their history for as long. Controls stay until you delete them. The audit-integrity check keeps
one checkpoint per tenant in `complianceCheckpoints` (the sequence and hash verified so far) and continues from it.
All five collections (`complianceControls`, `complianceExceptions`, `complianceResults`, `complianceRuns`,
`complianceCheckpoints`) are removed with their organization.

## Permissions

| Action                    | Methods                                                                                                                              |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `iam:compliance:read`     | `catalog`, `listControls`, `status`, `listRuns`, `listResults`, `listExceptions`, `exportEvidence`, `evidenceKeys`, `verifyEvidence` |
| `iam:compliance:evaluate` | `evaluate`                                                                                                                           |
| `iam:compliance:manage`   | `adoptFramework`, `createControl`, `updateControl`, `deleteControl`, `createException`, `approveException`, `revokeException`        |

Actions are checked on the tenant (`iam/{tenantId}`), or on the record a call acts on: the control for
`updateControl` and `deleteControl`, and the exception for `approveException` and `revokeException`. Evaluations read
the whole directory as the deployment, whoever triggers them. Results name people only by ID, and add their email
address or name only for callers allowed `iam:identities:read` on the tenant; still, `iam:compliance:read` shows
findings about people the caller may not otherwise read, so grant it to the people who answer to auditors. `evaluate`
returns statuses and counts, not findings. Exceptions take two holders of `iam:compliance:manage`: one proposes, the
other approves. A typical split gives the compliance team `iam:compliance:read` and `iam:compliance:manage`, and a CI
job or a reporting service `iam:compliance:evaluate`.

## Audit events

Every method records its operation event (`iam:compliance:read`, `iam:compliance:evaluate` or
`iam:compliance:manage`). These record what happened, subscribable as `compliance:*`:

| Event                          | Recorded when                                                                         | Resource      | Metadata                                                   |
| ------------------------------ | ------------------------------------------------------------------------------------- | ------------- | ---------------------------------------------------------- |
| `compliance:evaluate`          | An evaluation ran (actor: the caller, or `deployment-operator` for `evaluateAll`)     | The run       | `pass`, `fail`, `warn`, `not-applicable`, `digest`         |
| `compliance:control:fail`      | A control failed after a different status in its previous evaluation (outcome `deny`) | The control   | `key`, `checkId`, `status`, `previous`, `summary`          |
| `compliance:control:recover`   | A control that failed has another status now                                          | The control   | `key`, `checkId`, `status`, `previous`, `summary`          |
| `compliance:framework:adopt`   | `adoptFramework` adopted a framework                                                  | The tenant    | `framework`, `controls` (their keys)                       |
| `compliance:control:create`    | `createControl` added a control                                                       | The control   | `key`, `checkId`, `name`, `params`, `mappings`, `enabled`  |
| `compliance:control:update`    | `updateControl` changed a control                                                     | The control   | `key`, `before`, `after`                                   |
| `compliance:control:delete`    | `deleteControl` removed a control                                                     | The control   | `key`, `checkId`, `before`                                 |
| `compliance:exception`         | `createException` proposed an exception                                               | The exception | `controlKey`, `subject`, `expiresAt`, `status` (`pending`) |
| `compliance:exception:approve` | `approveException` approved one                                                       | The exception | `controlKey`, `subject`, `createdBy`, `expiresAt`          |
| `compliance:exception:revoke`  | `revokeException` ended or withdrew one                                               | The exception | `controlKey`, `subject`                                    |
| `compliance:evidence-export`   | `exportEvidence` produced a pack                                                      | The tenant    | `framework` (when given), `controls`, `digest`, `kid`      |

A control's first evaluation records neither `compliance:control:fail` nor `compliance:control:recover`, and deleting a
control revokes its exceptions without a `compliance:exception:revoke` each. See
[Events and webhooks](events.md#compliance-events).

## Errors

| Code                   | When                                                                                                                                                                                                                                                     |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `INVALID_INPUT`        | An unknown framework (also for `status` and `exportEvidence`) or check, a malformed key, an unknown parameter or one out of range, more than 50 mappings or 100 `controlKeys`, an `expiresAt` out of range, an exception for `audit-integrity` findings. |
| `CONFLICT` (409)       | A control with the key exists; approving an exception that is not pending, or has expired.                                                                                                                                                               |
| `LIMIT_EXCEEDED` (409) | The tenant would have more than 200 controls.                                                                                                                                                                                                            |
| `NOT_FOUND` (404)      | An unknown control or exception, or an exception for a control key the tenant does not have.                                                                                                                                                             |
| `ACCESS_DENIED` (403)  | The caller lacks the `iam:compliance:*` action; proposing or approving an exception for a finding about oneself; approving one's own exception.                                                                                                          |
| `RATE_LIMITED` (429)   | `evaluate` within a minute of the tenant's last evaluation.                                                                                                                                                                                              |

## Console

**Governance › Compliance** shows the last run's counts (passing, failing, warnings, when), a card per adopted
framework with each requirement's status and controls (disabled and stale ones marked) and a button to download its
evidence pack, buttons to adopt the frameworks not yet adopted, the controls with their latest result and findings
(stale results marked, people's names for directory readers) and an enable or disable button, a form to add a control,
the exceptions with their status, a form to propose one, an Approve button on pending ones and a Withdraw or Revoke
button on each, a button to download evidence for every control, and "Evaluate now".
