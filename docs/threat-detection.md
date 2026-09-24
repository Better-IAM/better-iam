# Threat detection and response

Better IAM watches its own audit trail for attacks on identities (ITDR: identity threat detection and response). It
reports password sprays, password and second-factor guessing, stolen sessions, replayed tokens, accounts taken over
and then locked in, self-granted administrator access, mass deletions, weakened security settings, and tampering with
the audit log itself. Detections about the same person, network, tenant, or directory connection are grouped into one
**incident** for investigation. Each identity gets a decaying **risk score** that policies read as
`principal.riskLevel` and `principal.riskScore`. Administrators respond by hand (end sessions, forget devices, contain
an account, block a network, send an alert), or define **playbooks** that respond automatically.

Everything lives in the `threats` API group. Reading needs `iam:threats:read`, tuning and triage need
`iam:threats:manage`, and acting on identities and networks needs `iam:threats:respond`, all on `iam/threats/...`.
People report activity on their own account ("this wasn't me") without any permission.

## How detection runs

Detection is a scheduled job, `iam.detectThreats()` (CLI `detect-threats`). Each run, for every active tenant:

1. **Reads the tenant's audit chain from a cursor.** The engine keeps one cursor per tenant: the sequence and hash of
   the last event it verified. It reads at most `maxEvents` unread events (default 2000, at most 20,000). A tenant
   with more waits for the next run and counts under `pending`. A tenant's first run starts one day back instead of
   replaying the whole trail.
2. **Verifies the hash chain as it goes.** Each event must follow the previous one: sequences are contiguous,
   `previousHash` links to the event before, and `hash` recomputes. A chain head moved back behind the cursor, or
   replaced at it, counts too. A break raises an `audit-tampering` detection (critical) and detection continues from
   the event as stored, so one break is reported once. The gap an `audit:prune` checkpoint explains is not a break:
   the engine continues after a prune even when its cursor was behind it.
3. **Evaluates the detection rules** over the new events together with the events before them that the rules'
   windows reach back to (the longest enabled window plus a day; one day and fifteen minutes by default). The
   module's own events (`threat:*`, and anything the `threat-detection` actor records) are verified but never fed to
   the rules.
4. **Records detections** once each, joins them to incidents, raises the identities' risk, learns sign-in baselines,
   advances the cursor, and runs the tenant's playbooks for the new detections, all in one transaction.

Reading the trail rather than hooking the code that writes it has three consequences. Detection sees everything any
writer records: the authentication service, SCIM, the OAuth provider, deployment jobs, and every server process. It
never slows down a sign-in or an API call. And it is not instant: a detection appears on the first run after the
activity, so the job's interval is the detection delay.

Every detection has a unique key made of its rule and a rule-chosen key: the triggering event for single-event rules,
or the burst for counting rules. Reading the same events again, overlapping runs, and a burst seen by several runs
never raise a second detection. Activity that never pauses raises at most one detection a day per subject and rule.
Two runs that overlap are safe: the writing transaction re-checks the cursor and the later one records nothing. When
rule evaluation fails for one tenant, that tenant records nothing and keeps its cursor, so the next run reads the same
events again. The other tenants are unaffected, and the failure is reported on the `threats:detect` observability span.

A run returns what it did:

| Field             | Meaning                                                                                        |
| ----------------- | ---------------------------------------------------------------------------------------------- |
| `tenants`         | Tenants read.                                                                                  |
| `eventsScanned`   | Audit events read and verified.                                                                |
| `detections`      | New detections recorded.                                                                       |
| `incidentsOpened` | Incidents opened by them.                                                                      |
| `responses`       | Playbook actions applied (skipped ones are not counted).                                       |
| `braked`          | Automatic containments held back by `maxAutomaticContainments`.                                |
| `chainBreaks`     | Tenants whose audit chain failed verification in this run.                                     |
| `pending`         | Tenants with more unread events than one run reads; the next run continues where this stopped. |

`threats.detect({ tenantId })` runs detection for one tenant right away (`iam:threats:manage` on
`iam/threats/detections`) and returns the same summary, for example behind a "Check now" button.

## Detection rules

`threats.rules({ tenantId })` lists every rule with its defaults, the bounds a tenant may tune it within, and the
setting in force. Rules are on by default. Counting rules fire when a key reaches the threshold within the sliding
window.

| Rule                           | Detects                                                                                           | Severity | Subject    | Default                   | MITRE ATT&CK |
| ------------------------------ | ------------------------------------------------------------------------------------------------- | -------- | ---------- | ------------------------- | ------------ |
| `password-spray`               | One network failing password sign-ins for many different accounts                                 | high     | network    | 10 accounts in 15 minutes | T1110.003    |
| `brute-force`                  | Many failed password sign-ins for one person                                                      | medium   | identity   | 10 in 15 minutes          | T1110.001    |
| `brute-force-success`          | A sign-in right after a run of failed attempts                                                    | high     | identity   | 5 failures in 30 minutes  | T1110        |
| `mfa-bombardment`              | Repeated wrong second-factor codes: the password was right                                        | high     | identity   | 5 in 15 minutes           | T1621        |
| `session-hijack`               | A session bound to one network presented from another                                             | high     | identity   | every occurrence          | T1550.004    |
| `new-network`                  | A privileged person signing in from a network not seen for them before                            | medium   | identity   | every occurrence          | T1078        |
| `dormant-reactivated`          | A sign-in to an account unused for longer than the dormancy period                                | medium   | identity   | 90 days (`dormantDays`)   | T1078        |
| `account-takeover-persistence` | Sign-in methods changed shortly after a risky sign-in                                             | high     | identity   | within 1 hour             | T1098        |
| `privilege-escalation`         | Someone granting an administrator role they now hold                                              | high     | identity   | every occurrence          | T1098.003    |
| `root-admin-granted`           | A person made a root administrator of the deployment                                              | high     | identity   | every occurrence          | T1098        |
| `mass-deletion`                | One actor deleting or revoking many identities, roles, policies, groups, bindings, keys or trusts | high     | identity   | 20 in 10 minutes          | T1531        |
| `directory-mass-change`        | A SCIM connection updating or deleting many people                                                | medium   | connection | 25 in 10 minutes          | T1531        |
| `impersonation-burst`          | One administrator starting many "view as" sessions                                                | medium   | identity   | 5 in 1 day                | T1078        |
| `denial-burst`                 | One actor denied many times (AI agents included): probing for access                              | medium   | identity   | 30 in 10 minutes          | T1069        |
| `recon-burst`                  | Far more administrative reads than usual, or many data-subject exports                            | low      | identity   | 300 reads in 10 minutes   | T1087        |
| `guardrail-weakened`           | A protection dropped from the sign-in policy, a network block lifted, or a detection rule off     | medium   | tenant     | every occurrence          | T1562        |
| `token-replay`                 | A web identity token presented a second time to assume a role                                     | high     | identity   | every occurrence          | T1550        |
| `audit-tampering`              | The tenant's audit hash chain no longer verifies                                                  | critical | tenant     | every break               | T1070        |
| `invariant-broken`             | A monitored access invariant stopped holding                                                      | medium   | tenant     | every `invariant:broken`  | T1098        |
| `user-reported`                | The account holder reported activity that was not them                                            | high     | identity   | every report              | T1078        |
| `upstream-signal`              | An upstream identity provider reported compromise, a disabled account or risk (Shared Signals)    | by event | identity   | every matched event       | T1078        |

What each rule reads, and the details that matter when tuning it:

- **Sign-in failures** (`password-spray`, `brute-force`, `mfa-bombardment`, `brute-force-success`) count
  `auth:signin:fail` events, which the authentication service records for known, active people only. Spray and
  password guessing count wrong passwords; second-factor guessing counts wrong codes; `brute-force-success` counts
  failures of any kind in the window before the sign-in and since the previous one. It is high when the successful
  sign-in came from a network that was failing, and one step lower otherwise.
- **Networks** are client addresses reduced to a key: an IPv4 address, or the /64 of an IPv6 address. Events without
  a parseable address never reach the network rules.
- **Sign-in baselines.** Every sign-in a person makes themselves (not through impersonation) is learned into their
  baseline: the last 25 networks, the last 10 user agents, and the time. `new-network` needs at least one known
  network, so an identity's first sign-in after detection is enabled only teaches. It reports privileged people only:
  owners, root administrators, and holders of a live standing binding (direct or through a group) of a role that
  grants `*` or `iam:*` on `*` without conditions. With `everyone: true` it reports everybody else too, at low
  severity. `dormant-reactivated` compares a sign-in with the last one the baseline holds, so it judges only accounts
  whose previous sign-in the engine saw.
- **Risky sign-ins** are the ones `brute-force-success`, `new-network`, and `dormant-reactivated` flag. For the window
  after one (an hour by default), `account-takeover-persistence` watches the person's own changes: turning off the
  second factor, adding a passkey, generating recovery codes, remembering a device, changing the email address or
  password, and creating an API key.
- `session-hijack` needs the tenant sign-in policy `bindSessionsToIp`: only then are sessions bound to a network and
  refused (and audited as `auth:session:mismatch`) elsewhere. One detection per session.
- `privilege-escalation` reads role bindings created by someone who is neither an owner nor a root administrator. The
  audit event names only the role, so a holder of an administrator role granting it to a colleague matches too; it
  fires at most once per actor, role, and day.
- `mass-deletion` counts identity deletions and offboarding, deletions of roles, policies, groups, bindings, webhooks
  and resource types, API key revocations, and trust revocations. `mass-deletion`, `impersonation-burst`,
  `denial-burst`, and `recon-burst` count identities only, never the deployment's own actors (`deployment-operator`,
  `threat-detection`, SCIM connections). `directory-mass-change` counts SCIM `UpdateUser` and `DeleteUser` per
  connection.
- `recon-burst` counts allowed `iam:*:read` operations (reading the threats module itself excepted), and separately
  data-subject exports (`identity:export`) at a threshold of the larger of 3 and one fiftieth of the read threshold.
- `guardrail-weakened` fires when the tenant sign-in policy drops `requireMfa`, `requireMfaForOwners`,
  `bindSessionsToIp`, `notifyNewSignIn`, or empties `allowedIpRanges`; when a network block is lifted
  (`security:network-unblock`); and when `threats.configure` turns a detection rule off (recorded against the person
  who did it, since the engine never reads the module's own events).
- `invariant-broken` reads the `invariant:broken` events of the `monitor-invariants` job. An enforced invariant is at
  least high.
- `upstream-signal` reads what the [Shared Signals receiver](shared-signals-receiver.md) recorded
  (`signal:received`) when it matched an upstream provider's event to a person of the tenant. The event sets the
  severity: `credential-compromise` and a `risk-level-change` to HIGH are high; `account-disabled`, `account-purged`,
  `account-credential-change-required` and a `risk-level-change` to MEDIUM are medium; `credential-change` is low.
  Session revocations and LOW risk raise nothing (the receiver can end sessions itself). Contain people with a
  playbook on this rule, for example `{ ruleIds: ['upstream-signal'], minSeverity: 'high' }`.

## Tuning

`threats.configure` changes a tenant's settings. Fields you leave out keep their value.

```ts
await iam.api.threats.configure(admin, {
  tenantId,
  rules: {
    'brute-force': { threshold: 20, windowMs: 30 * 60_000 },
    'new-network': { everyone: true }, // non-privileged people too, at low severity
    'recon-burst': { enabled: false },
    'mass-deletion': null, // back to every default
  },
  trustedNetworks: ['203.0.113.0/24', '2001:db8:1000::/48'], // office and VPN egress
  dormantDays: 60,
  riskHalfLifeHours: 48,
  notify: { owners: true, emails: ['soc@acme.test'] },
  maxAutomaticContainments: 5,
});
```

| Setting                         | Default    | Accepted                                                                                    |
| ------------------------------- | ---------- | ------------------------------------------------------------------------------------------- |
| `rules.{id}.enabled`            | on         | `true`, `false`                                                                             |
| `rules.{id}.severity`           | the rule's | `low`, `medium`, `high`, `critical`                                                         |
| `rules.{id}.threshold`          | the rule's | within the rule's `tunable.threshold` bounds (rules that count only)                        |
| `rules.{id}.windowMs`           | the rule's | within the rule's `tunable.windowMs` bounds (rules with a window only)                      |
| `rules['new-network'].everyone` | `false`    | `true` reports non-privileged people too, at low severity                                   |
| `trustedNetworks`               | none       | Up to 50 addresses or CIDR blocks, no wider than /8 (IPv4) or /32 (IPv6); replaces the list |
| `dormantDays`                   | 90         | 7 to 3650                                                                                   |
| `riskHalfLifeHours`             | 24         | 1 to 720                                                                                    |
| `notify`                        | nobody     | `owners` (active owners with a verified email) and up to 20 `emails`                        |
| `maxAutomaticContainments`      | 3          | 0 to 100                                                                                    |

`null` puts one field of a rule back to its default, and `null` for a whole rule drops every adjustment of it.
Threshold and window bounds are per rule: `threats.rules` returns them as `tunable`, and a value outside them, or a
threshold for a rule that does not count, is refused with `INVALID_INPUT`.

**Trusted networks** are the addresses you know: offices, VPN egress, CI runners. Network rules never report them,
detections never name them, and neither people nor playbooks can block them (the response is skipped as
`trusted-network`). Per-person rules still apply to sign-ins from a trusted network.

`configure` needs `iam:threats:manage` on `iam/threats/settings` and a recent sign-in. It is audited as
`threat:settings` with the changed keys, the rules whose behavior changed, the rules turned off, and the settings
weakened. Turning a rule off, or weakening detection another way (a higher threshold, a shorter window or a lower
severity on a rule that stays on, `new-network` no longer reporting everyone, a shorter risk half-life, a longer
dormancy period, a newly trusted network, a lower `maxAutomaticContainments`, fewer incident recipients), also records
a `guardrail-weakened` detection against the caller, so switching detection off is itself visible. A shorter half-life
decays every score at once, so nobody shortens it while detections raise their own risk (`ACCESS_DENIED`; root
administrators excepted), and contributions are kept for at least ten days, so restoring the half-life restores the
scores.
`threats.getSettings` returns the settings with every default applied and `configured: false` while the tenant has
never saved any.

## Incidents

A new detection joins the open incident about its subject, or opens one. There is at most one open (or investigating)
incident per subject: an identity, a network, the tenant, or a directory connection. The incident takes the highest
severity of its detections, lists up to 200 of them, and is retitled "N detections for X" once it spans more than one
rule. Resolving an incident closes it for good; the next detection about the same subject opens a new one.

A typical investigation:

```ts
const { openIncidents, investigating, riskyIdentities, contained, detections24h } =
  await iam.api.threats.summary(admin, { tenantId });

const { incidents } = await iam.api.threats.listIncidents(admin, {
  tenantId,
  status: 'open',
  severity: 'high',
});
const { incident, detections, notes, responses, risk } = await iam.api.threats.getIncident(admin, {
  tenantId,
  incidentId: incidents[0].id,
});

// Take it, write down what you found, and look at what the person did.
await iam.api.threats.updateIncident(admin, {
  tenantId,
  incidentId: incident.id,
  status: 'investigating',
  assigneeId: me,
});
await iam.api.threats.addNote(admin, {
  tenantId,
  incidentId: incident.id,
  body: 'Called Alice: she was not travelling.',
});
const trail = await iam.api.threats.timeline(admin, {
  tenantId,
  identityId: incident.identityId!,
  limit: 100,
});

// Respond, then close it.
await iam.api.threats.respond(admin, {
  tenantId,
  incidentId: incident.id,
  actions: [{ kind: 'contain' }, { kind: 'block-network', durationMs: 7 * 86_400_000 }],
  reason: 'Password sprayed and reused from a hosting provider',
});
await iam.api.threats.resolveIncident(admin, {
  tenantId,
  incidentId: incident.id,
  resolution: 'true-positive',
  note: 'Password reset with the person on the phone; account released.',
});
```

- Each detection carries its **evidence**: up to 20 audit event ids with the count, the time span, and the networks,
  identities, and actions involved, so a reviewer can open the underlying trail.
- `updateIncident` moves an incident between `open` and `investigating`, assigns it to an active identity of the
  tenant (`null` unassigns), or changes its severity. `addNote` adds notes of up to 4000 characters, at most 500 per
  incident, resolved ones included.
- `resolveIncident` closes it as `true-positive`, `false-positive`, or `benign`. Its open detections become
  `resolved`. A false positive or benign finding also takes their points out of the identities' risk.
- `dismissDetection` marks one open detection a false alarm and takes its points out of the risk; the incident stays
  open for a person to resolve.
- `timeline` lists an identity's recent audit events, newest first: what it did and what was done to it.
- `listDetections` pages through detections by status, rule, severity, identity, incident, and time.

| Permission            | Needed for                                                                                                                                              |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `iam:threats:read`    | `rules`, `getSettings`, `summary`, `listDetections`, `getDetection`, `listIncidents`, `getIncident`, `listRisk`, `getRisk`, `timeline`, `listPlaybooks` |
| `iam:threats:manage`  | `configure`, `dismissDetection`, `updateIncident`, `addNote`, `resolveIncident`, `createPlaybook`, `updatePlaybook`, `deletePlaybook`, `detect`         |
| `iam:threats:respond` | `respond`, `release`, `setRisk`                                                                                                                         |

They are checked on `iam/threats/settings`, `iam/threats/rules`, `iam/threats/detections[/{id}]`,
`iam/threats/incidents[/{id}]`, `iam/threats/risk[/{identityId}]`, `iam/threats/playbooks[/{id}]`, and
`iam/threats/responses`. Changes need a recent sign-in, except updating an incident and adding notes. A security
analyst role might hold `iam:threats:read` and `iam:threats:manage` on `iam/threats/*`, and an incident responder
`iam:threats:respond` as well.

## Identity risk

Every detection that concerns an identity (the subject, or the actor behind a tenant-level change) adds points to that
identity's risk:

| Severity | Points |
| -------- | ------ |
| low      | 10     |
| medium   | 25     |
| high     | 50     |
| critical | 80     |

Points halve every `riskHalfLifeHours` (24 by default). The score is the sum of what is left, capped at 100, and its
level is `none` below 10, `low` from 10, `medium` from 40, and `high` from 70. One high detection therefore puts a
person at 50 (`medium`), a day later at 25 (`low`), and after three days back to `none`, unless something else
happens. Scores are computed when they are read, so they decay without any job running. The newest 50 contributions
are kept, and contributions older than ten half-lives are dropped.

- **Overrides.** `threats.setRisk` with `low`, `medium`, or `high` sets a floor, such as "confirmed compromised",
  that holds until `expiresInMs` (one hour to 90 days) or indefinitely. The effective level is never below it. `none`
  clears the override and every contribution.
- **Clearing.** Dismissing a detection, or resolving its incident as a false positive or benign, takes its points
  out. A true positive keeps them, decaying as usual.
- **Nobody clears risk about themselves.** Detections about you are dismissed by another administrator, and incidents
  that raised your own risk are closed as false positives or benign by another administrator (both `ACCESS_DENIED`,
  unless you are a root administrator). Nobody sets their own risk level at all. A compromised administrator account
  therefore cannot erase its own signal.
- Every change of level is audited as `threat:risk-change` with the old and new level and the score.

`threats.listRisk` lists the identities at or above a level (default `low`), and contained ones, highest score first,
each with its contributions and what they still add. `threats.getRisk` returns one identity's risk (`none` when
nothing was ever detected).

## Risk in policies

Every decision whose policies mention them carries two context keys:

| Key                   | Type                            | Value                                            |
| --------------------- | ------------------------------- | ------------------------------------------------ |
| `principal.riskLevel` | `none`, `low`, `medium`, `high` | The effective level at the time of the decision  |
| `principal.riskScore` | number, 0 to 100                | The effective score, decay and override included |

Use them to take sensitive actions away from risky accounts while an incident is investigated, without touching
their roles:

```json
{
  "version": 1,
  "statements": [
    {
      "sid": "NoAdministrationWhileAtHighRisk",
      "effect": "deny",
      "actions": ["iam:*"],
      "resources": ["*"],
      "conditions": { "StringEquals": { "principal.riskLevel": "high" } }
    },
    {
      "sid": "NoPaymentsFromRiskyAccounts",
      "effect": "deny",
      "actions": ["payments:send", "payroll:*"],
      "resources": ["*"],
      "conditions": { "NumericGreaterThanEquals": { "principal.riskScore": 40 } }
    },
    {
      "sid": "ExportsOnlyWhenCalm",
      "effect": "allow",
      "actions": ["documents:export"],
      "resources": ["document/*"],
      "conditions": {
        "StringEquals": { "principal.riskLevel": ["none", "low"] },
        "Bool": { "principal.mfa": true }
      }
    }
  ]
}
```

- Risk follows the person. A role session they assumed carries their risk, a service account's or agent's key its
  own, and a delegated session (an agent acting for a person) the higher of the person's and the agent's.
- Simulated principals always get `none` and 0: access invariants, impact previews, policy simulation, and
  birthright (package rule) automation. An incident therefore never flips an invariant or stalls automation.
  `policies.test` defaults them to `none` and 0 too; pass other values in its `context` to try a document.
- The server owns both keys. Values that `resolveContext` or a plugin supplies are removed, and identity attributes
  cannot be named `riskLevel` or `riskScore`.
- Root administrators override policies, so a deny on risk does not stop them; contain the account instead.

See [policies](policies.md#risk-context).

## Responding

Five response actions exist, taken by a person through `threats.respond` or automatically by a playbook:

| Action            | Effect                                                                                                                                                                                        |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `revoke-sessions` | Ends the identity's sessions, the role sessions it assumed, and (for an agent) its delegated sessions, and deletes pending sign-in challenges. API keys are kept unless `keepApiKeys: false`. |
| `forget-devices`  | Deletes the identity's remembered devices, so the next sign-in asks for the second factor again.                                                                                              |
| `contain`         | Disables the identity until `threats.release`: every session except API keys ends, remembered devices and challenges go, and its keys are refused while it is disabled.                       |
| `block-network`   | Blocks the network for the tenant, like [`security.blockNetwork`](authentication.md), for `durationMs` (one minute to 30 days; one day by default).                                           |
| `notify`          | Emails the incident (template `threat-alert`) to the tenant's `notify` recipients.                                                                                                            |

```ts
const responses = await iam.api.threats.respond(admin, {
  tenantId,
  identityId: aliceId, // or incidentId, or network: '198.51.100.0/24'
  actions: [{ kind: 'revoke-sessions', keepApiKeys: false }, { kind: 'forget-devices' }],
  reason: 'Session cookie reused from another country',
});
```

`respond` takes exactly one target (an incident, whose subject it acts on, an identity, or a network), one to five
actions with each kind at most once, and a reason. It needs `iam:threats:respond` on the incident (on
`iam/threats/responses` without one) and a recent sign-in. A response to an identity or network with an open
incident is filed under that incident. Every action comes back as a response record, `applied` or `skipped` with a
reason: `not-identity` (an identity action on a network), `no-network`, `trusted-network`, `already-applied`
(already contained, or a block at least as long already covers the network), `inactive`, `no-incident`,
`no-transport`, `no-recipients`. Every applied action is audited as `threat:{action}`.

Protections apply to people responding:

- A root administrator's sessions are ended, and the account contained, only by a root administrator
  (`ACCESS_DENIED`). An owner is contained only by an owner of the tenant in person or a root administrator, as
  `identities.setStatus` requires (`ACCESS_DENIED`). The last owner cannot be contained (`LAST_OWNER`).
- Nobody contains themselves (`INVALID_INPUT`). Revoking your own sessions keeps the one you are responding from.
- A block may not cover your own address, either your session's or this request's (`INVALID_INPUT`), so you cannot
  lock yourself out. Trusted networks are never blocked.
- Blocks on the root tenant decide whether root administrators can sign in, so, as with `security.blockNetwork`, only
  a root administrator sets them (`ACCESS_DENIED`); playbooks skip them as `protected`.

**Containment** is reversible. The identity is disabled, its sessions end, and its API keys are refused while it stays
disabled. `threats.release({ tenantId, identityId, note })` makes it active again: it signs in as usual, and its keys
work again without being reissued. Its sessions stay ended and its risk is kept; member invitations it sent are
revoked at containment and stay revoked. Only an identity the threats module contained and that nothing else has
disabled, suspended, or re-enabled since can be released (`INVALID_TRANSITION` otherwise, and for an identity past its
`expiresAt`), a root administrator only by root. Changing the identity's status any other way
(`identities.setStatus`, `identities.offboard`, service accounts' `setStatus`, `agents.suspend` and `agents.resume`,
workflow steps) ends the containment, so a release never undoes what they did. Containing and releasing re-evaluate
the identity's rule-based access packages at once.

**Blocks** are ordinary tenant network blocks with the reason prefixed `threat: `: they refuse sign-ins, sessions, and
keys from the network, show in `security.listBlocks`, and lapse on their own. A network that a tenant or platform
block already covers for at least as long is skipped as `already-applied`; a shorter block on the same network is
renewed.

**Alerts** go to the addresses in `notify.emails` and, with `notify.owners`, to the tenant's active owners with a
verified email. They need the deployment's email transport (`authentication.sendEmail`). Playbooks email an incident
once, and again only when its severity has risen since; a person can send it again at any time.

## Playbooks

A playbook responds automatically: when a new detection matches its trigger, its actions run in order as the
`threat-detection` actor.

```ts
// Block spraying networks for a day and tell the security team.
await iam.api.threats.createPlaybook(admin, {
  tenantId,
  name: 'Block password sprays',
  trigger: { ruleIds: ['password-spray'] },
  actions: [{ kind: 'block-network', durationMs: 86_400_000 }, { kind: 'notify' }],
});

// Contain accounts that look taken over: stolen sessions, locked-in takeovers, and "this wasn't me".
await iam.api.threats.createPlaybook(admin, {
  tenantId,
  name: 'Contain taken-over accounts',
  trigger: { ruleIds: ['session-hijack', 'account-takeover-persistence', 'user-reported'] },
  actions: [{ kind: 'contain' }, { kind: 'notify' }],
});

// Page on anything high or critical, whatever the rule.
await iam.api.threats.createPlaybook(admin, {
  tenantId,
  name: 'Email the SOC',
  trigger: { minSeverity: 'high' },
  actions: [{ kind: 'notify' }],
});

// Replayed web identity tokens: end every session of the workload, keys included.
await iam.api.threats.createPlaybook(admin, {
  tenantId,
  name: 'Replayed tokens',
  trigger: { ruleIds: ['token-replay'], subjectTypes: ['identity'] },
  actions: [{ kind: 'revoke-sessions', keepApiKeys: false }],
});
```

- A trigger matches when every clause it sets matches: `ruleIds`, `minSeverity`, and `subjectTypes`. `{}` matches
  every detection.
- Playbooks run for new detections only, in the order they were created. Emails go out only through playbooks (or a
  person's `notify`): detection itself never emails anyone.
- **Automatic responses never touch owners or root administrators.** Containing one is skipped as `protected`
  (ending their sessions or forgetting their devices is allowed).
- **The brake.** A run contains at most `maxAutomaticContainments` identities per tenant (3 by default; 0 turns
  automatic containment off). Further containments are skipped as `braked`, counted in the run's `braked`, and
  audited once per run as `threat:response-braked`, so a noisy rule or a flood of forged events cannot lock out the
  whole organization.
- Trusted networks are never blocked, and a network the detection does not name is skipped as `no-network`.
- A tenant has at most 50 playbooks with unique names. Each keeps `runs` and `lastRunAt`; `updatePlaybook` can turn
  one off with `enabled: false`. Creating, changing, and deleting them needs `iam:threats:manage` and a recent sign-in.

## "This wasn't me"

People report suspicious activity on their own account from their own session, without any permission:

```ts
const report = await client.threats.reportSuspicious({
  tenantId,
  note: 'I got a sign-in email from a city I have never been to.',
  sessionId: unknownSession.id, // optional: a session in auth.listSessions they do not recognize
});
// { detectionId, incidentId, sessionsEnded, devicesForgotten }
```

The report records a `user-reported` detection (high), which raises the person's risk and opens an incident the
administrators see. It then ends every other session of the account except API keys (the reporting session stays),
deletes pending sign-in challenges, forgets remembered devices, and runs the tenant's playbooks. Follow it with a
password change and a new second factor.

It is accepted from an ordinary sign-in session of the account's own tenant only: not from an API key, a role
session, a delegated session, or another tenant (`ACCESS_DENIED`), and not while impersonating
(`IMPERSONATION_RESTRICTED`). A person may file five reports a day (`LIMIT_EXCEEDED` beyond that), and a tenant that
turned the `user-reported` rule off refuses reports with `FEATURE_DISABLED`. It is audited as `threat:user-report`,
with the two responses as `threat:revoke-sessions` and `threat:forget-devices`.

## Events, webhooks, and Shared Signals

Everything the module does is audited under `threat:*` actions: detections, incidents, risk changes, notes,
resolutions, settings, playbooks, and every response (see [events](events.md#threat-detection-events)). Detections
and automatic responses are recorded by the actor `threat-detection`, people's actions by the person. Subscribe a
webhook to `threat:*`, or to `threat:detection` and `threat:incident-open`, to forward them to a SIEM or a pager.

With the [Shared Signals transmitter](protocols.md#shared-signals-caep-and-risc), responses reach receivers that keep
their own sessions: `threat:revoke-sessions` is sent as CAEP `session-revoked` and `threat:contain` as RISC
`account-disabled`, so applications signed in through Better IAM end the account's sessions too.

The `threat-alert` email carries the incident's `incidentId`, `title`, `severity`, `subject`, `subjectType`,
`detections` (the count), `tenantName`, and the latest detection's `summary`. `renderDeliveryMessage` renders it;
give it a `links.threats` builder that receives `{ tenantId, incidentId?, signInUrl? }` and returns the incident's page
in your console. Without one the button falls back to `links.account`.

```ts
import { renderDeliveryMessage } from 'better-iam/auth/templates';

const rendered = renderDeliveryMessage(message, {
  appName: 'Acme Cloud',
  links: {
    threats: ({ tenantId, incidentId }) =>
      `https://admin.acme.test/orgs/${tenantId}/security/incidents/${incidentId ?? ''}`,
  },
});
```

## Deploying detection

Run the job every minute, beside `outbox`, from cron or a worker in your application:

```sh title="crontab"
* * * * *  better-iam detect-threats --config /etc/better-iam/better-iam.config.mjs && better-iam outbox --config /etc/better-iam/better-iam.config.mjs
```

```ts
setInterval(() => void iam.detectThreats().catch(reportError), 60_000).unref();
```

- The job needs no credential and is safe to overlap with itself. `--tenant ID` (`tenantId`) limits a run to one
  organization and `--max-events N` (`maxEvents`, 1 to 20,000) caps what one run reads per organization. When
  `pending` stays above zero, run it more often or raise the cap.
- Record client addresses. Sessions and sign-in events carry an IP only when the deployment knows it: behind a proxy,
  supply `http.clientInfo(request)` (see [deployment](deployment.md)). Without addresses the network rules
  (`password-spray`, `new-network`, network keys on detections) and `block-network` have nothing to work with; the
  per-person rules still work.
- Alerts need `authentication.sendEmail` and the `outbox` job to deliver them.
- The module keeps nine tenant-scoped collections (`threatDetections`, `threatIncidents`, `threatNotes`,
  `identityRisk`, `threatBaselines`, `threatCursors`, `threatSettings`, `threatPlaybooks`, `threatResponses`). They are
  removed with their tenant; an identity's baseline and risk record go when the identity is deleted. Detections,
  incidents, and responses are kept as history and are not swept.
- `audit-prune` can run as usual. Prune only events the engine has read, or they are never judged; the engine resumes
  after the prune checkpoint without reporting a break.

## Limits

- **No geolocation.** There is no impossible-travel rule and no country or ASN data: networks are addresses and
  /64 prefixes. Feed your own intelligence in through `trustedNetworks` and blocks.
- **Refusals that leave no audit event are invisible.** Attempts against unknown or disabled accounts, rate-limited
  attempts (`RATE_LIMITED`), requests from blocked or disallowed networks, invalid bearer tokens and API keys, wrong
  passwordless codes, and failed passkey assertions record nothing, so no rule counts them. A spray aimed at
  addresses that do not exist is not seen; rate limits and network blocks are the defense there.
- **Addresses need `http.clientInfo`** (see above).
- **Detection is not inline.** Activity is judged on the next run after it happened, and policies see the new risk
  from then on. Pair risk-based policies with short sessions for the most sensitive actions.
- **Chain verification is tamper evidence, not tamper proof.** It catches events edited, removed, or inserted outside
  the recorder, and a chain head moved back. Someone with full write access to the database can rewrite the events,
  the head, and the cursor consistently. Archive the audit log continuously to storage they cannot reach
  (`audit-archive`).
- **Bursts are deduplicated per day.** Activity that continues for days raises one detection per day per subject and
  rule, not one per attempt; the evidence shows the peak.
