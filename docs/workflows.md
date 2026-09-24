# Identity lifecycle workflows

Lifecycle workflows automate what happens when people join an organization, move within it, and leave it (joiner,
mover, leaver). A workflow has three parts:

- **A trigger**: what starts a run for a person. They joined, a watched attribute changed, they were disabled, a date
  they carry came round, or someone started the workflow by hand.
- **A scope**: the people it applies to, written in the
  [access-package rule language](policies.md#automatic-assignment-birthright).
- **Steps**: what a run does for that person, in order. Steps change groups and packages, send emails, sign the person
  out, disable, enable or delete the account, change attributes and expiry, record events for webhooks, and wait for
  hours or days in between.

Steps run with the rights of the administrator who saved the workflow (its owner when the run started), checked again
at every step. Nobody can automate what they could not do by hand, and a run stops when its owner loses the rights. A
daily brake holds back a workflow that would start more runs than expected. Everything lives in the `workflows` API
group (`POST /api/iam/workflows/{method}`, `client.workflows.*` in the browser), and the deployment runs the work that
is due with `iam.workflows.runDue()`.

Workflows complement [birthright access packages](policies.md#automatic-assignment-birthright). A package rule keeps
access in line with who a person is right now. A workflow does something once, when something happens: it sends a
welcome email, signs a leaver out, or deletes their account 30 days later.

```ts
const workflow = await iam.api.workflows.create(admin, {
  tenantId,
  name: 'Engineering joiners',
  trigger: { kind: 'joiner' },
  scope: { include: [{ StringEquals: { 'principal.department': 'Engineering' } }] },
  steps: [
    { kind: 'add-to-group', groupId: engineering.id },
    {
      kind: 'send-email',
      to: 'subject',
      subject: 'Welcome to {organization}, {name}',
      body: 'You joined {attribute.department}.',
    },
  ],
});
```

## Defining a workflow

`create` (`iam:workflows:manage`) takes:

| Field             | Meaning                                                                                      |
| ----------------- | -------------------------------------------------------------------------------------------- |
| `name`            | Up to 120 characters, unique in the tenant (ignoring case).                                  |
| `description`     | Optional, up to 1000 characters.                                                             |
| `trigger`         | What starts runs ([triggers](#triggers)).                                                    |
| `scope`           | Who it applies to ([scope](#scope)). Without one, it applies to every person.                |
| `steps`           | 1 to 20 steps ([steps](#steps)).                                                             |
| `enabled`         | `true` by default. A disabled workflow starts no runs.                                       |
| `includeExisting` | Joiner workflows: also run for people who were already active. `false` by default.           |
| `maxRunsPerDay`   | The [daily brake](#the-daily-brake), 1 to 10000: 25 when a step takes access away, else 200. |

A tenant holds at most 100 workflows. The caller becomes the workflow's owner (`ownerId`, `ownerName`); see
[authority](#authority). The result also carries `version` (1, incremented by every update), `activeSince` (when the
workflow was created, or last restarted) and `brakedOn` (the day the brake last held runs back).

`update` changes any field; fields you leave out keep their values, `null` clears `scope`, and `null` or an empty
string clears `description`. Changing the trigger, or enabling a disabled workflow, **restarts** it: `activeSince`
becomes now, so joiners and dates count from then, and mover and leaver baselines are taken again. Other changes
(steps, scope, name, brake) keep `activeSince`. Runs already started keep the steps they started with, and the rights
of the owner who approved them, unless the update passes `activeRuns: 'cancel'`, which cancels the workflow's pending,
running, waiting and failed runs (`'keep'` is the default).

Disabling a workflow stops new runs; runs already in progress, including those waiting, carry on. Cancel them with
`cancelRun`, or with `activeRuns: 'cancel'` in the same update. `delete` removes the workflow and its baselines and
cancels its pending, running and waiting runs; finished runs stay as history until they expire
([runs](#runs)).

## Triggers

| `trigger`                                 | A run starts for a person when                                                                                      | Occurrence          |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | ------------------- |
| `{ kind: 'joiner' }`                      | The person is active and was created at or after `activeSince` (any time, with `includeExisting`). Once per person. | `joiner`            |
| `{ kind: 'mover', attributes }`           | One of the watched attributes changed while the person is active.                                                   | `mover:{n}:{hash}`  |
| `{ kind: 'leaver' }`                      | The person went from active to disabled.                                                                            | `leaver:{n}`        |
| `{ kind: 'date', attribute, offsetDays }` | `offsetDays` days after (before, when negative) a date the person carries has passed, while the person is active.   | `date:{YYYY-MM-DD}` |
| `{ kind: 'manual' }`                      | Only when someone starts it with `run`.                                                                             | `manual:{id}`       |

Each occurrence starts one run however often the workflow is evaluated: the workflow remembers, per person, the
latest 20 occurrences it started (with the baseline, in `workflowSubjects`), so the joining or a date does not fire
again after its run has been swept away. A restart (a new trigger, or enabling the workflow again) resets these with
the baselines, so the workflow starts afresh. Only people start runs: service accounts and agents never do, and `run`
refuses them.

Triggers are evaluated by `iam.workflows.runDue()` and by `iam.workflows.subscribe()` ([scheduling](#scheduling)).
With `subscribe()` a change to people is seen within moments; otherwise at the next `runDue()`. A value that changes
and changes back between two evaluations is not seen at all.

### Joiners

A joiner workflow runs once for each active person created at or after its `activeSince`. People created disabled run
when they are first seen active. With `includeExisting: true` it also runs for everyone who was already active, for
example to roll out a new tool to the whole organization; the daily brake still applies, so raise `maxRunsPerDay` for
a large organization first. Such a workflow runs for everyone again after a restart, since a restart forgets whom it
ran for.

### Movers and leavers

When a mover or leaver workflow is created or restarted, it records a **baseline** for every person
(`workflowSubjects`): a mover the current values of its watched attributes, a leaver the person's status. Only
changes made afterwards fire, so creating a workflow never fires for the whole organization. People who join later
get their baseline the first time the workflow sees them; their first values are not a move.

- **Movers** watch 1 to 20 attributes: declared identity attributes (`permissions.identityAttributes`) or
  `managerId`. A change fires once, and changing back is a new change that fires again. Several watched attributes
  changed together start one run. A change made while the person is disabled, or while they are outside the scope,
  becomes the new baseline without a run.
- **Leavers** fire when a person who was active is disabled: by an administrator (`identities.setStatus`), by
  offboarding, by SCIM deprovisioning, or when their account expires and the purge job disables it. Disabling,
  enabling and disabling again fires twice. An account deleted outright, without being disabled first, does not fire:
  there is nobody left to act on.

### Dates

A date trigger fires `offsetDays` (-365 to 3650, 0 by default) after a date the person carries:

- `attribute` is `createdAt`, `expiresAt`, or a declared **string** identity attribute holding an ISO 8601 date such
  as `startDate`: `2026-10-01` (midnight UTC) or a date and time with its offset, such as `2026-10-01T09:00:00Z` or
  `2026-10-01T09:00+02:00`. A time without an offset is ambiguous and ignored, like any value that is missing or not
  a date: the person is skipped.
- A run starts at the first evaluation after the date plus the offset has passed, for people who are active and in
  scope then. `{ attribute: 'startDate', offsetDays: -7 }` fires a week before the start date,
  `{ attribute: 'expiresAt', offsetDays: -14 }` two weeks before an account expires.
- The occurrence is the target day, so a date that moves to another day fires again: a start date pushed back by a
  week runs the workflow again a week later.
- Dates more than a day before the workflow's `activeSince` never fire, so a new "30 days after the start date"
  workflow does not run for everyone who started years ago.

### Manual

A `manual` workflow never starts by itself. `run` starts any workflow for up to 100 people you choose, whatever its
trigger, and ignores its scope.

## Scope

A scope is `{ include, exclude? }`: `include` lists 1 to 10 condition sets, any of which may match, and `exclude` up
to 10, any of which leaves the person out. Each set is a policy `conditions` block over the keys of the
[package rule language](policies.md#automatic-assignment-birthright):

- `principal.id`, `principal.kind`, `principal.owner`, and `principal.{name}` for each declared identity attribute;
- `identity.email`, `identity.emailDomain`, `identity.emailVerified` and `identity.managerId`;
- `identity.groups` (the person's group memberships that no access package created), and `identity.teams` and
  `identity.departments` (their [teams and departments](teams-and-departments.md), with those above them).

```ts
{
  include: [{ StringEquals: { 'principal.department': ['Engineering', 'Design'] } }],
  exclude: [{ Bool: { 'principal.contractor': true } }],
}
```

Without a scope a workflow applies to every person. The scope is checked when the trigger fires; a run that started
carries on if the person leaves the scope. Session keys and policy variables are refused (`INVALID_INPUT`), malformed
conditions answer `INVALID_POLICY`, and groups, teams and departments must exist in the tenant.

## Steps

| Step                     | Fields                  | The owner needs                                                                       | What it does                                                                                                                                       |
| ------------------------ | ----------------------- | ------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `add-to-group`           | `groupId`, `days?`      | `iam:groups:update` on the group                                                      | Adds the person to the group, ending after `days` (1 to 3650) when set. Skipped when they are already a member.                                    |
| `remove-from-group`      | `groupId`               | `iam:groups:update` on the group                                                      | Removes the person from the group. Skipped when they are not a member.                                                                             |
| `remove-from-all-groups` |                         | `iam:groups:update` on each group, checked as the step runs                           | Removes the person from every group they joined directly. Memberships a team or an access package manages are left to it.                          |
| `assign-package`         | `packageId`, `days?`    | `iam:packages:assign` on the package, and what assigning it by hand needs             | Assigns the package, ending after `days` when set, with the justification `Workflow: {name}`.                                                      |
| `revoke-packages`        | `packageId?`            | `iam:packages:assign` on the package (without one: on each package, as the step runs) | Revokes the person's assignment of the package, or of every package, except assignments a package rule made. Skipped when there is none.           |
| `send-email`             | `to`, `subject`, `body` | `iam:identities:read` on the person                                                   | Queues a `workflow-message` email ([emails](#emails)).                                                                                             |
| `revoke-sessions`        |                         | `iam:identities:update` on the person                                                 | Signs the person out everywhere: ends their sessions and forgets their remembered devices and pending sign-in challenges.                          |
| `disable`                |                         | `iam:identities:update` on the person                                                 | Disables the account, ends its sessions and revokes the invitations the person sent that nobody accepted yet. Skipped when it is already disabled. |
| `enable`                 |                         | `iam:identities:update` on the person                                                 | Enables the account. Skipped when it is active; `INVALID_TRANSITION` when it has expired. A root administrator needs an owner who is root too.     |
| `set-attributes`         | `attributes`            | `iam:identities:update` on the person                                                 | Sets declared identity attributes; `null` clears one.                                                                                              |
| `set-expiry`             | `days`                  | `iam:identities:update` on the person                                                 | Sets the account's `expiresAt` to `days` (1 to 3650) from now, or clears it with `null`.                                                           |
| `delete`                 |                         | `iam:identities:delete` on the person                                                 | Deletes the account as `identities.delete` does. Must be the last step.                                                                            |
| `emit-event`             | `name`                  | none                                                                                  | Records `workflow:event` with the name, for webhooks and subscribers.                                                                              |
| `wait`                   | `hours`                 | none                                                                                  | Pauses the run for 1 to 8760 hours; it carries on at the first evaluation after that.                                                              |

- A workflow has 1 to 20 steps, at least one of them not a wait. It cannot end with a wait, may wait at most 5 times,
  and may only `delete` as its last step. Unknown fields are refused.
- The groups and packages steps name must exist when the workflow is saved (`INVALID_INPUT` for an unknown group,
  `NOT_FOUND` for a package), and group steps cannot name a team's backing group (`TEAM_MANAGED`): add people to the
  team instead.
- "What assigning by hand needs" is `iam:bindings:create` on each role of the package, `iam:groups:update` on each of
  its groups, and a grant authority when it has roles, as for `packages.assign`. Adding to or removing from a group
  that has role bindings also needs the use of the grant authorities behind them, as `groups.addMember` does.
- `set-attributes` names declared identity attributes only, with values of the declared type (strings up to 2048
  characters without control characters).
- `emit-event` names are 1 to 64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter, such
  as `person.left`.
- `revoke-packages` leaves assignments a [package rule](policies.md#automatic-assignment-birthright) made to the rule,
  which removes them itself once the person stops matching (`packages.revoke` refuses them too).
- A step that finds nothing to do is recorded as `skipped`, not failed. After a step changes the person, the
  package rules are reconciled for them at once.

The steps `remove-from-all-groups`, `revoke-packages`, `revoke-sessions`, `disable` and `delete` take access away.
A workflow with any of them needs a recent sign-in to save, run by hand or retry, and its daily brake defaults to 25.

## Authority

### Saving makes you the owner

Whoever creates or updates a workflow becomes its owner, and saving checks that they could do every step by hand:

- They act in their own right: a person's own signed-in session, or an API key. Role sessions, session tokens,
  delegated agent sessions and impersonation are refused (`ACCESS_DENIED`).
- They belong to the workflow's organization (root administrators may manage any).
- They hold every permission the steps need: the directory permissions on the tenant (`iam/{tenantId}`), since the
  workflow will act on anyone in it, and the group and package permissions on the groups and packages named. For
  `assign-package` they also need what assigning the package by hand needs. A missing permission answers
  `ACCESS_DENIED` naming the step and the permission.
- A workflow with a step that takes access away needs a recent sign-in (`RECENT_AUTH_REQUIRED`).
- `send-email` steps with a fixed address may only write to an active member of the organization or to a domain it
  has [verified](enterprise.md), so a workflow cannot mail people's details to outsiders (`INVALID_INPUT`).

Every update, a rename included, makes the caller the owner and checks their rights again. That is how another
administrator takes over the workflow of someone who left. The workflow also remembers whether the owner saved it
from a session with a second factor, and its runs are decided with that `principal.mfa`, so policies that ask for MFA
before directory changes keep applying to automation.

### Runs act as the owner who approved them

A run records the workflow's owner when it starts, and its steps use that owner's rights until it ends or someone
retries it, whoever edits the workflow in between: a new editor never lends their rights to step lists someone else
approved. Before every step:

- the run's owner must be active and unexpired, or the run fails with `OWNER_INACTIVE`;
- the organization must be active, or it fails with `TENANT_INACTIVE`;
- the run owner's permissions for the step are decided again, now on the person (`iam/{identityId}`) and on the group
  or package, or it fails with `ACCESS_DENIED`. `remove-from-all-groups`, and `revoke-packages` without a package,
  check each group or package they touch, and a fixed `send-email` address is checked again.

Removing the owner's role, disabling them or offboarding them therefore stops their runs at the next step. Someone
with the rights takes over by retrying the failed runs (`retryRun` makes the caller the run's owner) or cancelling
them, and by saving the workflow so that new runs have an active owner. The changes steps make are audited with the
run's owner as the actor.

### Protected accounts

- The steps that take access away, `set-attributes` and `set-expiry` never act on an owner or a root administrator:
  the run fails with `PROTECTED_RESOURCE`. They never act on the run's own owner either (`INVALID_INPUT`).
- Nobody changes their own account through a workflow: `set-attributes`, `set-expiry` and `enable` never act on the
  run's owner or on whoever started or retried the run (`ACCESS_DENIED`), just as people cannot edit their own
  record by hand.
- `enable` reaches a root administrator only when the run's owner is a root administrator too (`ACCESS_DENIED`).

### Running by hand

`run` (`iam:workflows:run`) needs, besides the permission, the steps' permissions over each person named (checked on
`iam/{identityId}`), from a session or API key of the caller's own, and a recent sign-in when a step takes access
away. It refuses to name the caller when a step would change their own account. The steps then run with the
workflow owner's rights as always, so both the caller and the owner must be allowed.

`retryRun` needs `iam:workflows:run`, the permissions of the remaining steps over the person, and a recent sign-in
when one of them takes access away. Retrying approves the remaining steps: the caller becomes the run's owner (and
`startedBy`), and the steps run with the caller's rights from then on.

## Runs

A run is one execution of a workflow for one person:

- `pending`: started, not yet picked up. `run`, `retryRun` and `runDue` pick it up at once.
- `running`: a worker holds it with a five-minute lease, renewed at every step. When a worker dies, the next `runDue`
  after the lease lapses carries on.
- `waiting`: paused by a `wait` step until `nextAt`.
- `completed`, `failed` (with `error: { code, message }`), or `cancelled`.

Each step runs in its own transaction and appends a result:
`{ index, kind, outcome: 'done' | 'skipped' | 'failed', at, detail?, code? }`. `detail` says what happened (the group
name, `2 packages`, `not in Engineering`, `until 2026-10-31T09:00:00.000Z`), and a failed result carries the error
`code`. A failed step changes nothing, and the steps before it stay done.

A run keeps the steps as they were when it started (`steps`, `workflowVersion`), with the owner who approved them.
Editing the workflow changes new runs only: a leaver waiting 30 days still deletes the account after someone removes
the `delete` step from the workflow. Cancel runs you no longer want, or save the edit with `activeRuns: 'cancel'`.

- `cancelRun` stops a pending, running, waiting or failed run. Steps already done stay done. A completed or cancelled
  run answers `INVALID_TRANSITION`.
- `retryRun` resumes a failed run at the step that failed, after you fix the cause (a group that was deleted, an owner
  who left), with your rights ([running by hand](#running-by-hand)). Steps already done are not repeated.
- `listRuns` lists runs newest first, by `workflowId`, `identityId` or `status`, and `getRun` returns one. They name
  people (`identityName`, and the workflow's `ownerName` in `list` and `get`) only for callers who may also read the
  directory (`iam:identities:read` on the tenant); otherwise they list IDs.

Finished runs (completed, failed or cancelled) are kept for 180 days (`expiresAt`), then `iam.sweepExpired()` deletes
them. Runs in progress never expire.

## The daily brake

`maxRunsPerDay` caps how many runs a workflow's trigger starts per day (UTC). It defaults to 25 for a workflow with a
step that takes access away and 200 otherwise. The workflow counts the runs its trigger started today; when an
evaluation finds more people than the rest of the day's allowance, it starts runs up to the allowance and holds the
others back. The first time that happens on a day, it records `workflow:brake` (outcome `deny`) and `brakedOn`.

The held changes are not lost: their mover and leaver baselines stay where they were, so they start at a later
evaluation, the next day within that day's allowance, or as soon as someone raises the limit with `update` (which
also clears `brakedOn`). Runs started with `run` neither count toward the brake nor are held by it.

The brake is there for mass changes: a directory sync that disables everyone, or an import that rewrites every
department, should not become mass deletion. Look at what fired before raising the limit.

## Previewing

`preview` (`iam:workflows:read`) shows what a workflow would do now, without changing anything:

- `inScope`: the active people its scope matches;
- `wouldStart`: the people a run would start for at the next evaluation, with the occurrence, before the daily brake
  (empty while the workflow is disabled);
- `upcoming`: for date workflows, people whose date falls within the next 30 days;
- `steps`: whether the workflow's owner still holds each step's permissions on the tenant, with a `reason` when not.

People carry their names and email addresses only when the caller may also read the directory (`iam:identities:read`
on the tenant); otherwise `name` is the person's ID.

## Scheduling

| Job                         | How often         | Does                                                                        |
| --------------------------- | ----------------- | --------------------------------------------------------------------------- |
| `iam.workflows.runDue()`    | every few minutes | Starts the runs triggers call for, and carries on pending and waiting runs. |
| `iam.workflows.subscribe()` | once, at start-up | Evaluates an organization's workflows within moments of each change.        |
| `iam.dispatchAuditHooks()`  | every minute      | Delivers audit events to subscribers, `subscribe()` included.               |

`iam.workflows.runDue({ tenantId?, limit? })` evaluates every enabled workflow that has a trigger, then executes the
runs that are due (pending, waiting past `nextAt`, and running with a lapsed lease), oldest first, at most `limit`
(500 by default, up to 10000). It returns `{ started, executed, completed, failed, waiting }`. A workflow whose
evaluation fails (a lock timeout, a record another process changed) is skipped until the next run without stopping
the others. Dates and waits only move on through it, and it catches up on anything `subscribe()` missed.

`iam.workflows.subscribe()` reacts to the audit events that can change who a workflow fires for, in every
organization that has an enabled workflow with a trigger: changes to identities (`iam:identities:*`, `identity:*`),
groups, teams, departments, workflows, and SCIM provisioning. It runs `runDue` for that organization in the
background, a moment later and once for a burst of changes, so audit dispatch never waits for it. Changes a workflow's
own steps made (`via: 'workflow'`) do not trigger it: other workflows see them at the next `runDue()`. It needs
`iam.dispatchAuditHooks()` (the same function as `iam.events.dispatch()`) running in the same process, and returns the
unsubscribe function. `iam.workflows.idle()` resolves once the evaluations it scheduled have finished, for tests and
graceful shutdown.

```ts
// In the worker process:
const stop = iam.workflows.subscribe();
setInterval(() => void iam.dispatchAuditHooks(), 60_000);
setInterval(() => void iam.workflows.runDue(), 5 * 60_000);
```

`workflows.evaluate` (`iam:workflows:run`) does the same for one organization on demand, and from the CLI
`better-iam api workflows.evaluate tenantId=...` runs it as a token job. The console subscribes and runs `runDue()`
every five minutes.

## Emails

A `send-email` step sends to `to`: `subject` (the person's own address), `manager` (their manager's, while the manager
is active), or a fixed address that belongs to an active member of the organization or is at one of its verified
domains, such as `hr@acme.test`. Fixed addresses are checked when the workflow is saved and again when the step runs.
The owner needs `iam:identities:read` on the person, since the email carries their details. `subject` is up to 200
characters, and `body` is plain text up to 5000 characters in which each line becomes a paragraph. Both may use
placeholders:

| Placeholder          | Filled with                                                               |
| -------------------- | ------------------------------------------------------------------------- |
| `{name}`             | The person's name                                                         |
| `{email}`            | Their email address                                                       |
| `{organization}`     | The organization's name                                                   |
| `{workflow}`         | The workflow's name                                                       |
| `{attribute.<name>}` | An identity attribute, such as `{attribute.department}`; empty when unset |

Other text in braces is left as written. The step is skipped, not failed, when the deployment has no email delivery
callback (`authentication.sendEmail`) or there is no address to send to.

The message is queued in the delivery outbox (`iam.auth.dispatchOutbox()` sends it) with template `workflow-message`
and payload `{ tenantId, tenantName, workflowName, subject, body }`, the filled subject cut at 300 characters and the
body at 10000. `renderDeliveryMessage` renders it with the subject as the title, one paragraph per line, and a
"Review your account" button when `links.account` is given.

## Permissions

| Action                 | Methods                                        |
| ---------------------- | ---------------------------------------------- |
| `iam:workflows:manage` | `create`, `update`, `delete`                   |
| `iam:workflows:read`   | `list`, `get`, `preview`, `listRuns`, `getRun` |
| `iam:workflows:run`    | `run`, `retryRun`, `cancelRun`, `evaluate`     |

Actions are checked on the tenant (`iam/{tenantId}`) for `create`, `list`, `listRuns` and `evaluate`, on the workflow
(`iam/{workflowId}`) for `update`, `delete`, `get`, `preview` and `run`, and on the run (`iam/{runId}`) for `getRun`,
`cancelRun` and `retryRun`. Saving, `run` and `retryRun` also need the steps' own permissions
([authority](#authority)), and the readers show people's names only to callers with `iam:identities:read` on the
tenant.

## Audit events

Every method records its operation event (`iam:workflows:manage`, `iam:workflows:read` or `iam:workflows:run`). Runs
record these, subscribable as `workflow:*`:

| Event                   | Recorded when                                                              | Resource     | Metadata                                               |
| ----------------------- | -------------------------------------------------------------------------- | ------------ | ------------------------------------------------------ |
| `workflow:run:start`    | A run started (actor `deployment-operator`, or the caller for `run`)       | The run      | `workflowId`, `identityId`, `occurrence`               |
| `workflow:step`         | A step other than a wait was done or skipped (actor `deployment-operator`) | The run      | `workflowId`, `identityId`, `index`, `kind`, `outcome` |
| `workflow:run:complete` | A run finished its last step (actor `deployment-operator`)                 | The run      | `workflowId`, `identityId`                             |
| `workflow:run:fail`     | A step failed (actor `deployment-operator`, outcome `deny`)                | The run      | `workflowId`, `identityId`, `index`, `code`            |
| `workflow:brake`        | The daily brake held runs back, once a day (outcome `deny`)                | The workflow | `held`, `startedToday`, `maxRunsPerDay`                |
| `workflow:event`        | An `emit-event` step ran (actor: the run's owner)                          | The person   | `name`, `via`, `workflowId`, `runId`                   |

The changes steps make are recorded as the ordinary events of those changes, with the run's owner as the actor and
`via: 'workflow'`, `workflowId` and `runId` added to the metadata, so webhooks and outbound provisioning see them like
any other change:

| Step                                                          | Event                      | Resource    | Metadata                                                                       |
| ------------------------------------------------------------- | -------------------------- | ----------- | ------------------------------------------------------------------------------ |
| `add-to-group`, `remove-from-group`, `remove-from-all-groups` | `iam:groups:update`        | The group   | `identityId`, `added` or `removed`                                             |
| `assign-package`                                              | `package:assign`           | The package | `packageId`, `packageName`, `identityId`, `bindings`, `memberships`, `skipped` |
| `revoke-packages`                                             | `package:revoke`           | The package | `packageId`, `identityId`                                                      |
| `revoke-sessions`                                             | `identity:revoke-sessions` | The person  |                                                                                |
| `disable`, `enable`, `set-attributes`, `set-expiry`           | `iam:identities:update`    | The person  | `status`, `attributes` (names only), or `expiresAt`                            |
| `delete`                                                      | `identity:delete`          | The person  | `kind`                                                                         |

Subscribe a [webhook](events.md#workflow-events) to `workflow:run:fail` and `workflow:brake` to hear about runs that
need a person, and to `workflow:event` to hand work to other systems.

## Errors

| Code                         | When                                                                                                                                                                                                                                                                                                                                                |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `INVALID_INPUT`              | A definition fails validation (trigger, steps, scope keys, an unknown group, a fixed email address outside the organization); `run` names a service account or agent; a step that takes access away, `set-attributes` or `set-expiry` reaches the run's own owner.                                                                                  |
| `INVALID_POLICY`             | A scope condition is malformed.                                                                                                                                                                                                                                                                                                                     |
| `TEAM_MANAGED` (409)         | A group step names a team's backing group.                                                                                                                                                                                                                                                                                                          |
| `CONFLICT` (409)             | Another workflow of the tenant has the name.                                                                                                                                                                                                                                                                                                        |
| `LIMIT_EXCEEDED` (409)       | The tenant already has 100 workflows.                                                                                                                                                                                                                                                                                                               |
| `ACCESS_DENIED` (403)        | Saving, `run` or `retryRun` without the steps' permissions, with a temporary or delegated credential, or from another organization; a step the run's owner no longer has the rights for; a step that would change the account of the run's owner or of whoever started or retried it; `enable` of a root administrator by an owner who is not root. |
| `RECENT_AUTH_REQUIRED` (403) | Saving, running by hand, or retrying a workflow with a step that takes access away without a recent sign-in.                                                                                                                                                                                                                                        |
| `OWNER_INACTIVE` (409)       | A run reached a step while its owner is disabled, deleted or expired.                                                                                                                                                                                                                                                                               |
| `PROTECTED_RESOURCE` (403)   | A step that takes access away, `set-attributes` or `set-expiry` reached an owner or a root administrator.                                                                                                                                                                                                                                           |
| `INVALID_TRANSITION` (409)   | `cancelRun` of a finished run; `retryRun` of a run that has not failed; `enable` of an expired account.                                                                                                                                                                                                                                             |
| `NOT_FOUND` (404)            | An unknown workflow, run, package or person; a run whose person was deleted in the meantime.                                                                                                                                                                                                                                                        |
| `TENANT_INACTIVE` (403)      | The organization is suspended when a step runs.                                                                                                                                                                                                                                                                                                     |

Steps also fail with the errors of the operations they perform, such as `LEGAL_HOLD` for a `delete` while the person
is under a [legal hold](privacy.md#legal-holds) or `SOD_CONFLICT` for an `assign-package` that would break a
separation-of-duties rule. A failing step fails its run (the code is on the run's `error` and the step's result)
rather than an API call; only `run` and `retryRun` return the runs they executed.

## Examples

### Joiner: welcome and base access

Everyone who joins gets the base group, the laptop kit for their first 90 days, a welcome email, and their manager an
introduction:

```ts
await iam.api.workflows.create(admin, {
  tenantId,
  name: 'Welcome',
  trigger: { kind: 'joiner' },
  steps: [
    { kind: 'add-to-group', groupId: everyone.id },
    { kind: 'assign-package', packageId: laptopKit.id, days: 90 },
    {
      kind: 'send-email',
      to: 'subject',
      subject: 'Welcome to {organization}, {name}',
      body: 'Your account is ready.\nYour base access is in place; ask your manager for anything else.',
    },
    {
      kind: 'send-email',
      to: 'manager',
      subject: '{name} joins {organization}',
      body: '{name} ({email}) starts in {attribute.department}. Their base access is ready.',
    },
  ],
});
```

The owner needs `iam:groups:update` on the group, what assigning the package by hand needs, and
`iam:identities:read` on the tenant for the emails. To act before the first day instead, use a date trigger on a
`startDate` attribute: `trigger: { kind: 'date', attribute: 'startDate', offsetDays: -7 }`.

### Mover: department change

When someone changes department or manager, remove the groups they were added to by hand, tell the new manager, and
let other systems know. Department access itself is best granted by a birthright package rule on
`principal.department`, which moves with the person:

```ts
await iam.api.workflows.create(admin, {
  tenantId,
  name: 'Department moves',
  trigger: { kind: 'mover', attributes: ['department', 'managerId'] },
  steps: [
    { kind: 'remove-from-all-groups' },
    {
      kind: 'send-email',
      to: 'manager',
      subject: '{name} moved to {attribute.department}',
      body: 'Their earlier group memberships were removed. Request what they need in their new role.',
    },
    { kind: 'emit-event', name: 'person.moved' },
  ],
});
```

`remove-from-all-groups` takes access away, so saving needs a recent sign-in and the brake defaults to 25 runs a
day, and the owner needs `iam:groups:update` on the groups people are removed from. Memberships that teams and access
packages manage stay.

### Leaver: remove access now, delete after 30 days

```ts
await iam.api.workflows.create(admin, {
  tenantId,
  name: 'Leavers',
  trigger: { kind: 'leaver' },
  steps: [
    { kind: 'remove-from-all-groups' },
    { kind: 'revoke-packages' },
    {
      kind: 'send-email',
      to: 'manager',
      subject: '{name} has left {organization}',
      body: 'Their access was removed today. The account will be deleted in 30 days.',
    },
    { kind: 'emit-event', name: 'person.left' },
    { kind: 'wait', hours: 720 },
    { kind: 'delete' },
  ],
});
```

Disabling the person starts the run: groups and packages go at once, and the run waits 30 days before deleting the
account. Packages a package rule assigned are left to the rule, which does not assign or remove anything for
disabled people; deleting the account removes them. The owner needs `iam:identities:delete` and
`iam:identities:read` on the tenant, and saving needs a recent sign-in. The run does not check whether the person
came back: if they are enabled again within the 30 days, find their waiting run
(`listRuns({ tenantId, identityId, status: 'waiting' })`) and cancel it. A legal hold fails the `delete` step with
`LEGAL_HOLD`; retry the run once the hold is released (retrying makes you the run's owner, so you need the rights for
`delete` yourself).

## Storage

Workflows, their runs, and the mover and leaver baselines with the occurrences each person already ran live in the
`workflows`, `workflowRuns` and `workflowSubjects` collections, and are removed with their organization. Finished runs
are swept 180 days after they end.

## Console

**Access › Workflows** lists the workflows with their trigger, steps, runs of the last 30 days (active and failed),
owner and an enable or disable button, the recent runs, a form for a new workflow (trigger, scope and steps as JSON,
"include existing", daily brake) with a step reference, example step lists and the group and package IDs, and a "Run
due now" button. Each workflow has its own page: the definition, a warning when the brake stopped it, the preview (in
scope, would start now, coming up, and whether the owner may do each step), a form to run it for chosen people, its
runs with retry and cancel, an edit form, and delete.
