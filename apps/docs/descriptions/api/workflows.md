# workflows

Identity lifecycle workflows: joiner, mover and leaver automation. A workflow has a trigger (a person joined, a
watched attribute changed, the person was disabled, a date they carry came round, or someone started it by hand), a
scope in the access-package rule language, and up to 20 steps that run for each person the trigger fires for: group
and package changes, emails, sign-outs, disabling, enabling, attribute and expiry changes, deletion, events for
webhooks, and waits. Steps run with the rights of the administrator who saved the workflow (its owner when the run
started), checked again at every step, and a daily brake holds back a workflow that would start more runs than
expected. See the [lifecycle workflows guide](/docs/guides/governance/workflows); the repository guide is
`docs/workflows.md`.

## Triggers and scope

`trigger` is one of `{ kind: 'joiner' }` (active people created after the workflow was enabled, or everyone with
`includeExisting`), `{ kind: 'mover', attributes }` (1 to 20 declared identity attributes or `managerId`, compared
with a baseline taken when the workflow starts), `{ kind: 'leaver' }` (an active person was disabled),
`{ kind: 'date', attribute, offsetDays }` (`offsetDays`, -365 to 3650, after `createdAt`, `expiresAt` or a declared
string attribute holding an ISO 8601 date, or a date and time with its offset; dates more than a day before the
workflow started never fire, and a date that moves fires again) and `{ kind: 'manual' }` (only [`run`](#run)). Each
person runs each occurrence once (until the workflow restarts): the joining, the nth move or departure, the target
day of a date. Only people are
subjects, never service accounts or agents.

`scope` is `{ include, exclude? }`, each a list of up to 10 policy condition sets over the keys of
[package rules](/docs/guides/privileged-access/automatic-assignment#keys-a-rule-may-test): `principal.id`,
`principal.kind`, `principal.owner`, declared attributes as `principal.NAME`, `identity.email`,
`identity.emailDomain`, `identity.emailVerified`, `identity.managerId`, `identity.groups`, `identity.teams` and
`identity.departments`. Without a scope a workflow applies to every person. The scope is checked when the trigger
fires; `run` ignores it.

## Steps

Each step is `{ kind, ...fields }`, and the owner needs the permission shown, on the person (`iam/IDENTITY_ID`) or
the group or package named:

| Step | Fields | Permission |
| --- | --- | --- |
| `add-to-group` | `groupId`, `days?` (1 to 3650) | `iam:groups:update` on the group |
| `remove-from-group` | `groupId` | `iam:groups:update` on the group |
| `remove-from-all-groups` | none | `iam:groups:update` on each group, checked as it runs; team and package memberships are left alone |
| `assign-package` | `packageId`, `days?` | `iam:packages:assign` on the package, plus what assigning it by hand needs |
| `revoke-packages` | `packageId?` | `iam:packages:assign` on the package, or on each package revoked; assignments a package rule made are left to the rule |
| `send-email` | `to` (`subject`, `manager`, or an address of a member or a verified domain), `subject`, `body` | `iam:identities:read` |
| `revoke-sessions`, `disable`, `enable` | none | `iam:identities:update` |
| `set-attributes` | `attributes` (declared ones; `null` clears) | `iam:identities:update` |
| `set-expiry` | `days` (1 to 3650, or `null`) | `iam:identities:update` |
| `delete` | none; last step only | `iam:identities:delete` |
| `emit-event` | `name` | none |
| `wait` | `hours` (1 to 8760); at most 5, never last | none |

Emails fill `{name}`, `{email}`, `{organization}`, `{workflow}` and `{attribute.NAME}` and are sent as the
`workflow-message` template; they are skipped without an email delivery callback. `remove-from-all-groups`,
`revoke-packages`, `revoke-sessions`, `disable` and `delete` take access away: saving, running or retrying such a
workflow needs a recent sign-in, and its brake defaults to 25 runs a day instead of 200. These steps,
`set-attributes` and `set-expiry` never act on owners or root administrators (`PROTECTED_RESOURCE`) or on the run's
owner (`INVALID_INPUT`), and `set-attributes`, `set-expiry` and `enable` never change the account of the run's owner
or of whoever started or retried it (`ACCESS_DENIED`).

## Owner and runs

Saving makes the caller the owner. The caller must act in their own right (a person's own session or an API key,
never a role session, session token, delegated session or impersonation), belong to the organization, and hold every
step's permission (on the tenant, and on the groups and packages named), or the save answers `ACCESS_DENIED`. The
workflow keeps whether the owner's session had a second factor, and runs are decided with that `principal.mfa`.

A run records the owner when it starts and uses that owner's rights until it ends: a later editor never lends their
rights to runs already started. Each step is authorized again as the run's owner on the person: a missing permission
fails the run with `ACCESS_DENIED`, and an owner who is disabled, deleted or expired fails it with `OWNER_INACTIVE`.
[`retryRun`](#retryrun) makes the caller the run's owner. A run (`pending`, `running`, `waiting`, `completed`,
`failed`, `cancelled`) keeps the steps it started with and a result per step (`done`, `skipped` or `failed`, with a
`detail` and, on failure, a `code`); finished runs are swept 180 days after they end. Runs are started and carried on
by the scheduler job `iam.workflows.runDue()` (every few minutes) and by `iam.workflows.subscribe()`, which reacts to
changes to people within moments while `iam.dispatchAuditHooks()` runs.

## Permissions

`iam:workflows:manage` covers `create`, `update` and `delete`; `iam:workflows:read` covers `list`, `get`, `preview`,
`listRuns` and `getRun`; `iam:workflows:run` covers `run`, `retryRun`, `cancelRun` and `evaluate`. Actions are checked
on `iam/TENANT_ID` for `create`, `list`, `listRuns` and `evaluate`, on the workflow (`iam/WORKFLOW_ID`) for `update`,
`delete`, `get`, `preview` and `run`, and on the run (`iam/RUN_ID`) for `getRun`, `cancelRun` and `retryRun`. The
readers name people (`ownerName`, `identityName`, and names and emails in `preview`) only for callers who also hold
`iam:identities:read` on the tenant; otherwise they list IDs.

## cancelRun

Stops a pending, running, waiting or failed run; steps already done stay done.

- **Permission:** `iam:workflows:run` on the run.
- **Audited as:** `iam:workflows:run`.
- **Errors:** `INVALID_TRANSITION` (409) when the run already completed or was cancelled; `NOT_FOUND` when the run is
  not in this tenant.

Cancel a leaver's waiting run when they come back before the account is deleted: the run does not check whether the
person was enabled again. The result is the cancelled run. To cancel every run of a workflow while changing it, pass
`activeRuns: 'cancel'` to [`update`](#update).

```ts
const { runs } = await iam.api.workflows.listRuns(admin, { tenantId, identityId, status: 'waiting' });
for (const run of runs) await iam.api.workflows.cancelRun(admin, { tenantId, runId: run.id });
```

## create

Creates a workflow owned by the caller, who must hold every permission its steps use.

- **Permission:** `iam:workflows:manage` on the tenant, plus each step's permission on the tenant, group or package,
  and a recent sign-in when a step takes access away.
- **Audited as:** `iam:workflows:manage`.
- **Errors:** `INVALID_INPUT` for an invalid trigger, scope or steps (an undeclared attribute, a date attribute that is
  not a string, an unknown group, more than 20 steps or 5 waits, a trailing wait, `delete` before the last step, an
  email `to` that is not `subject`, `manager`, an active member's address or an address at a verified domain);
  `INVALID_POLICY` for a malformed scope condition; `TEAM_MANAGED` (409) for a group step naming a team's backing
  group; `NOT_FOUND` for an unknown package; `CONFLICT` (409) when a workflow has the name; `LIMIT_EXCEEDED` (409) past
  100 workflows; `ACCESS_DENIED` without a step's permission or from a role session, session token, delegated session
  or impersonation; `RECENT_AUTH_REQUIRED`.

`enabled` defaults to true and `includeExisting` to false. `maxRunsPerDay` (1 to 10000) defaults to 25 when a step
takes access away and 200 otherwise. Mover and leaver workflows take everyone's current values as their baseline, so
only later changes fire. The result is the workflow with `ownerId`, `ownerName`, `version` 1 and `activeSince`.

```ts
await iam.api.workflows.create(admin, {
  tenantId,
  name: 'Leavers',
  trigger: { kind: 'leaver' },
  steps: [
    { kind: 'remove-from-all-groups' },
    { kind: 'revoke-packages' },
    { kind: 'wait', hours: 720 },
    { kind: 'delete' },
  ],
});
```

## delete

Deletes a workflow and cancels its pending, running and waiting runs; finished runs stay as history.

- **Permission:** `iam:workflows:manage` on the workflow.
- **Audited as:** `iam:workflows:manage`.
- **Errors:** `NOT_FOUND` when the workflow is not in this tenant.

The mover and leaver baselines go with it. The result is `{ deleted: true, runsCancelled }`. To stop new runs but
keep the workflow, disable it with [`update`](#update) (`enabled: false`).

## evaluate

Evaluates this organization's workflows and runs whatever is due now, instead of waiting for the scheduler.

- **Permission:** `iam:workflows:run` on the tenant.
- **Audited as:** `iam:workflows:run`; the runs record `workflow:*` events as usual.

It does what `iam.workflows.runDue({ tenantId })` does: starts the runs triggers call for (within the daily brake)
and carries on pending runs, waits that have ended, and runs whose worker lapsed. The result is
`{ started, executed, completed, failed, waiting }`. Steps run with each run owner's rights, not the caller's.

## get

Returns one workflow with run statistics and its 50 most recent runs.

- **Permission:** `iam:workflows:read` on the workflow.
- **Audited as:** `iam:workflows:read`.
- **Errors:** `NOT_FOUND` when the workflow is not in this tenant.

`runs` counts runs started in the last 30 days (`last30Days`), those in progress (`active`) and `failed`, with
`lastRunAt`. `recentRuns` lists runs newest first, with each person's `identityName` for callers who may read the
directory. `brakedOn` is the day the daily brake last held runs back.

## getRun

Returns one run with its steps and results.

- **Permission:** `iam:workflows:read` on the run.
- **Audited as:** `iam:workflows:read`.
- **Errors:** `NOT_FOUND` when the run is not in this tenant.

The run carries the `steps` it started with and `workflowVersion`, the `occurrence` that fired (`joiner`,
`mover:N:HASH`, `leaver:N`, `date:YYYY-MM-DD` or `manual:ID`), `stepIndex`, `nextAt` while waiting, the `results`,
`startedBy` for runs started or retried by hand, and `error` when it failed.

## list

Lists the tenant's workflows by name, with run statistics.

- **Permission:** `iam:workflows:read` on the tenant.
- **Audited as:** `iam:workflows:read`.

Each workflow carries its definition, `ownerId` (and `ownerName` for callers who may read the directory), and `runs`
(`last30Days`, `active`, `failed`, `lastRunAt`).

## listRuns

Lists runs, newest first, optionally of one workflow, one person or one status.

- **Permission:** `iam:workflows:read` on the tenant.
- **Audited as:** `iam:workflows:read`.
- **Errors:** `INVALID_INPUT` for a `limit` outside 1 to 500 or a malformed filter.

Filter by `workflowId`, `identityId` and `status`; page with `limit` (100 by default) and `offset`. The result is
`total` and `runs`, each with `identityName` for callers who may read the directory. Finished runs are swept 180 days
after they end.

## preview

Shows what a workflow would do right now, without changing anything.

- **Permission:** `iam:workflows:read` on the workflow.
- **Audited as:** `iam:workflows:read`.
- **Errors:** `NOT_FOUND` when the workflow is not in this tenant.

The result has `inScope` (active people the scope matches), `wouldStart` (people a run would start for at the next
evaluation, with the occurrence, before the daily brake; empty while the workflow is disabled), `upcoming` (date
workflows: people whose date falls within 30 days, with the time) and `steps` (whether the workflow's owner still holds
each step's permission on the tenant, with a `reason` when not). People carry their names and emails only for callers
who may read the directory; otherwise `name` is the ID.

```ts
const preview = await iam.api.workflows.preview(admin, { tenantId, workflowId });
const blocked = preview.steps.filter((step) => !step.allowed);
```

## retryRun

Resumes a failed run at the step that failed, with the caller's rights.

- **Permission:** `iam:workflows:run` on the run, the permissions of the remaining steps over the person from a
  session or API key of the caller's own, and a recent sign-in when a remaining step takes access away.
- **Audited as:** `iam:workflows:run`; the run records `workflow:*` events as usual.
- **Errors:** `INVALID_TRANSITION` (409) when the run has not failed; `ACCESS_DENIED` without the remaining steps'
  permissions, or when a remaining step would change the caller's own account; `RECENT_AUTH_REQUIRED`; `NOT_FOUND`
  when the run is not in this tenant.

Retrying approves the remaining steps: the caller becomes the run's owner and `startedBy`, and the steps run with the
caller's rights until the next wait before the call returns. Steps already done are not repeated. Fix what failed
first, such as a group that was deleted or a legal hold, and retry runs that failed with `OWNER_INACTIVE` to take them
over. The result is the run, listed by ID, which may have failed again.

## run

Runs a workflow now for up to 100 people you choose, whatever its trigger and scope.

- **Permission:** `iam:workflows:run` on the workflow, the steps' permissions over each person, and a recent sign-in
  when a step takes access away.
- **Audited as:** `iam:workflows:run`, plus `workflow:run:start` for each person with the caller as the actor.
- **Errors:** `INVALID_INPUT` for an empty list, more than 100 people, or a service account or agent; `NOT_FOUND` for
  an unknown or deleted person; `ACCESS_DENIED` without a step's permission over a person, when the caller names
  themself for a workflow that would change their own account, or from a role session, session token, delegated
  session or impersonation; `RECENT_AUTH_REQUIRED`.

Steps run until the first wait before the call returns, with the workflow owner's rights (both the caller and the
owner must be allowed). A step that fails fails that person's run, not the call. The result lists the runs by ID.
Runs started this way neither count toward the daily brake nor are held by it, and disabled people may be named.

```ts
const [result] = await iam.api.workflows.run(admin, {
  tenantId,
  workflowId,
  identityIds: [identityId],
});
if (result.status === 'failed') console.warn(result.error);
```

## update

Edits a workflow; the caller becomes its owner and must hold the steps' permissions.

- **Permission:** `iam:workflows:manage` on the workflow, plus each step's permission, and a recent sign-in when a
  step takes access away.
- **Audited as:** `iam:workflows:manage`.
- **Errors:** as for [`create`](#create), and `INVALID_INPUT` for an `activeRuns` other than `keep` or `cancel`;
  `NOT_FOUND` when the workflow is not in this tenant.

Fields you leave out keep their values; `scope: null` removes the scope, and `description: null` or `''` clears the
description. Changing the trigger, or enabling a disabled workflow, restarts it: joiners and dates count from now, and
mover and leaver baselines are taken again. Runs already started keep their steps and the owner who approved them;
`activeRuns: 'cancel'` cancels the workflow's pending, running, waiting and failed runs instead. Passing
`maxRunsPerDay` clears `brakedOn`. Saving, even without changes, is how an administrator takes over a workflow whose
owner left, for the runs that start from then on.

```ts
// Take the workflow over and raise the brake after checking what fired.
await iam.api.workflows.update(admin, { tenantId, workflowId, maxRunsPerDay: 100 });
```
