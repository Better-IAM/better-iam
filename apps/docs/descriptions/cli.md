# cli

The `better-iam` command runs the work that does not belong in a web request: creating and upgrading the schema,
creating the first administrator, health checks, the scheduled jobs that deliver, expire, remind, reconcile, and clean
up, audit verification and archiving, configuration as code, and moving a deployment between databases. It is the
`bin` of `@better-iam/cli`, and `runCli(argv)` from the same package (also exported as `better-iam/cli`) runs a
command from your own scripts.

Every command that touches the deployment loads your application configuration: `--config`, else
`BETTER_IAM_CONFIG`, else the nearest `better-iam.config.mjs` (or `.js`, `.ts`, `.mts`, `.cjs`) in the working
directory or a parent, else `BETTER_IAM_DATABASE_URL` and `BETTER_IAM_SECRET` with no file at all. The file is a module
whose default export is the options you pass to `betterIam()`, a function (sync or async) that returns them and
receives `{ command, env, cwd }`, or an instance you already created. It may also export `cli = { defaults }` (flag
defaults per command) and `commands` (project commands built with `defineCommand`). It runs
as JavaScript with access to your database and secrets, so point it only at trusted files, and give the CLI the same
environment (`BETTER_IAM_SECRET`, database location, `BETTER_IAM_PREVIOUS_SECRETS`) as your application.

Commands come in three kinds:

- **Deployment operations** (`migrate`, `bootstrap`, `recover-root`, `doctor`, `outbox`, `purge`, `sweep`, `digest`,
  `remind`, `reconcile`, `close-certifications`, `monitor-invariants`, `audit-verify`, `audit-export`,
  `audit-prune`, `audit-archive`, `rotate-secrets`, and the `store-*` commands) need no credential. They work on
  storage with the deployment's authority, and the ones that change access record audit events as
  `deployment-operator`. Whoever can run them with your configuration holds the database and the secret, so protect
  that configuration like a root credential.
- **Member commands** (`config-export`, `config-plan`, `config-apply`, `analyze`, `report`, `mine-roles`,
  `check-invariants`, `whoami`, `api`, `can`, `explain`, and `who-can`) act as the session token or API key in
  `BETTER_IAM_TOKEN`, or the session saved by `login` when it is unset. They run in process through the configuration
  or against a running server with `--url` (`BETTER_IAM_URL`), and read `--tenant` from `BETTER_IAM_TENANT` or the saved
  session. They are authorized and audited exactly like the same call from the console, so use the API key of a
  service account whose role holds only the permissions the command needs.
- **Offline commands** (`init`, `secret`, `config-validate`, `audit-verify-archive`, `profiles`, and `completion`)
  touch no database.

Results are printed as indented JSON on standard output (`purge`, `outbox`, `audit-prune`, and `audit-export` keep
their one-line result); `--format compact` prints one line, `--format json` indents, `--format table` aligned
columns, and `--query PATH` (`summary.create`, `findings[].kind`) only part of the result. Every flag also takes the
`--flag=value` form, and `better-iam help <command>` lists a command's flags with their defaults and environment
variables. A failure prints `CODE: message` on standard error, often followed by a `Hint:` line naming the next step
(a generic message for errors that are neither Better IAM nor system errors; `BETTER_IAM_DEBUG=1` shows them), and
exits with status 2 for a command-line mistake and 1 otherwise.
Unknown commands fail with `INVALID_COMMAND`, flags a command does not take with `INVALID_ARGUMENT`, and member
commands without a token with `MISSING_ENV`. Several commands also exit 1 on purpose when they find something, for CI
and alerting: `doctor --strict` (`DOCTOR_FINDINGS`), `config-plan --fail-on-drift` (`CONFIG_DRIFT`),
`analyze --fail-on` (`FINDINGS`), `check-invariants --fail-on-broken` (`INVARIANTS_BROKEN`),
`reconcile --fail-on-attention` (`RECONCILE_ATTENTION`), `audit-verify` (`AUDIT_CHAIN_BROKEN`), `audit-archive`
(`AUDIT_ARCHIVE_FAILED`), `audit-verify-archive` (`AUDIT_ARCHIVE_INVALID`), `rotate-secrets`
(`UNREADABLE_SECRETS`), `config-validate --strict` (`CONFIG_WARNINGS`), and `can` (`ACCESS_DENIED`). Each of them
prints its JSON result first, so the job log keeps the details.

## Scheduling the job commands

Better IAM starts no background work of its own. Messages wait in the outbox, expired access waits for the purge,
and package rules wait for reconciliation until something runs the matching command, or the matching instance
function from a worker in your application (see [Scheduled jobs](/docs/operations/jobs)). Every job below is safe to
rerun and to overlap with itself, and `doctor` reports the ones that have stopped running.

| Command | Cadence | Why |
| --- | --- | --- |
| `outbox` | Every minute | Delivers email, SMS, and webhooks. `doctor` warns when messages wait more than 15 minutes. |
| `audit-archive` | Every few minutes, at least hourly | Keeps the independent audit copy current. `doctor` warns about unarchived events older than a day. |
| `reconcile` | Every 15 minutes, after `purge` | Rule-based access packages only see SCIM, invitation, attribute, and group changes through it. |
| `purge` | Hourly, at least daily | Ends expired access and removes deleted tenants. `doctor` warns when expired records are a day old. |
| `sweep` | Hourly or daily, beside `purge` | Stops storage growing with traffic. `doctor` warns about records due for more than two days. |
| `monitor-invariants` | Hourly, and after configuration changes | Records `invariant:broken` and `invariant:restored` for webhooks to alert on. |
| `close-certifications` | Hourly or daily | Applies auto-closing certification campaigns once they are due. |
| `digest`, `remind`, then `outbox` | Daily | Emails owners and people about access that ends soon. |
| `audit-prune` | Per your retention policy, after archiving | Deletes each tenant's old audit events. |
| `report`, `analyze --fail-on` | Nightly | Member jobs for a ticket, chat channel, or alert. |
| `mine-roles` | Weekly | A role-mining snapshot for access reviews. |
| `config-plan --fail-on-drift`, `check-invariants --fail-on-broken` | Every deploy, and nightly | CI gates against drift and broken guardrails. |
| `doctor --strict` | After each deploy, and as a health check | Fails on any error or warning finding. |

```sh title="crontab"
CONFIG=/etc/better-iam/better-iam.config.mjs
# Every minute: deliver email, SMS, and webhooks.
* * * * *         better-iam outbox --config $CONFIG
# Every 5 minutes: continuous audit archiving.
*/5 * * * *       better-iam audit-archive --config $CONFIG
# Hourly: expire, sweep, then apply package rules; reconcile again every quarter hour.
0 * * * *         better-iam purge --config $CONFIG && better-iam sweep --config $CONFIG && better-iam reconcile --config $CONFIG --fail-on-attention
15,30,45 * * * *  better-iam reconcile --config $CONFIG --fail-on-attention
# Hourly: guardrails and due certification campaigns.
30 * * * *        better-iam monitor-invariants --config $CONFIG && better-iam close-certifications --config $CONFIG
# Daily: owner digest and personal reminders, then deliver them.
0 7 * * *         better-iam digest --config $CONFIG && better-iam remind --config $CONFIG && better-iam outbox --config $CONFIG
```

If your application registers subscribers with `iam.events.subscribe`, run the outbox step in that process instead
(`iam.auth.dispatchOutbox()` and `iam.events.dispatch()` every minute): the `outbox` command also dispatches queued
audit hooks, and the events it dispatches never reach subscribers that live in another process.

## init

Writes a starter `better-iam.config.mjs` for SQLite, PostgreSQL, or libSQL.

- **When:** once, when you add Better IAM to a project.
- **Needs:** nothing. It touches no database.
- **Fails with:** `CONFIG_EXISTS` when the file already exists (it never overwrites one); `INVALID_ARGUMENT` for a
  `--database` other than `sqlite`, `postgres`, or `libsql`.

Flags:

- `--config PATH` sets where the file is written (default `better-iam.config.mjs`, or `better-iam.config.ts` with
  `--typescript`).
- `--database sqlite|postgres|libsql` picks the storage adapter (default `sqlite`).
- `--typescript` writes a typed `better-iam.config.ts` (loading it needs Node.js 22.18 or later).

The generated file is a `defineConfig` factory, so importing it opens no database; the CLI calls it with
`{ command, env, cwd }`, and your server uses `betterIam(await configOptions(config))`. It reads its settings from the
environment: `BETTER_IAM_SECRET`, `BETTER_IAM_BASE_URL` (default `http://localhost:3000`),
`BETTER_IAM_PREVIOUS_SECRETS` (comma-separated, used during a secret rotation), and the database location:
`BETTER_IAM_DATABASE` for SQLite (default `./better-iam.db`), `BETTER_IAM_DATABASE_URL` and
`BETTER_IAM_DATABASE_TOKEN` for libSQL, or `DATABASE_URL` for PostgreSQL. It starts with sign-up disabled, the
catalog permission mode, an example resource type, a `cli` export with flag defaults, and an empty `commands` list for
project commands. Edit it, add a `sendEmail` callback, set `BETTER_IAM_SECRET` to a random value of at least 32
characters (`better-iam secret` prints one), then run `migrate`.

```bash
better-iam init --database postgres --config better-iam.config.mjs
```

## migrate

Creates or upgrades the database schema and applies plugin migrations and one-time data upgrades.

- **When:** on every deploy, before the new version starts serving, and once before `bootstrap`.
- **Needs:** the database the configuration points at. No credential.
- **Calls:** [`iam.initialize()`](/docs/reference/api#initialize).

It is idempotent, and instances migrating at the same time wait for one another instead of failing. Upgrades that
add indexes (`0002_query_indexes`, `0004_expiry_indexes`) build them inside the migration transaction, which blocks
IAM writes on large tables while it runs, and the first run after upgrading to the chained audit log backfills it in
one transaction: run those upgrades in a maintenance window. `store-import` and `store-copy` apply only the core
schema, so run `migrate` after them for plugin migrations. It prints `Database and plugin migrations applied.`

```bash
better-iam migrate --config /etc/better-iam/better-iam.config.mjs
```

## bootstrap

Creates the root tenant and the first root administrator of a new installation.

- **When:** once, after the first `migrate`.
- **Needs:** `BETTER_IAM_ROOT_EMAIL` and `BETTER_IAM_ROOT_PASSWORD` (at least 12 characters and accepted by your
  password policy); `BETTER_IAM_ROOT_NAME` is optional (default `Root administrator`).
- **Fails with:** `MISSING_ENV` without the email or password; `ALREADY_INITIALIZED` when a root tenant exists;
  `WEAK_PASSWORD` or `BREACHED_PASSWORD` for a password the policy refuses.
- **Calls:** [`iam.bootstrap()`](/docs/reference/api#bootstrap), audited as `root:bootstrap`.

Secrets come from the environment only, never from arguments, so they stay out of shell history and process lists.
It prints the new root tenant, the administrator's public identity, and `mfaEnrollmentRequired: true`: root
administrators always need MFA, so the first sign-in enrolls a factor before the account can do anything. Keep the
tenant ID. `doctor` reports `not-bootstrapped` until this command has run.

```bash
export BETTER_IAM_ROOT_EMAIL=platform-admin@example.com
export BETTER_IAM_ROOT_PASSWORD="$(cat /run/secrets/better-iam-root-password)"
better-iam bootstrap --config better-iam.config.mjs
```

## recover-root

Creates an additional root administrator when no one can sign in as root any more.

- **When:** during an incident, from a trusted machine with the production configuration.
- **Needs:** `BETTER_IAM_ROOT_EMAIL` (an address that is not in the root tenant yet), `BETTER_IAM_ROOT_PASSWORD`,
  and optionally `BETTER_IAM_ROOT_NAME`.
- **Fails with:** `MISSING_ENV`; `NOT_INITIALIZED` before `bootstrap` has run; `IDENTITY_EXISTS` when the email
  already belongs to an identity in the root tenant; `WEAK_PASSWORD` or `BREACHED_PASSWORD`.
- **Calls:** [`iam.recoverRoot()`](/docs/reference/api#recoverroot), audited as `root:recover`.

It does not reset an existing administrator's password or MFA. It adds a new root administrator with a verified
email, which enrolls MFA at its first sign-in. Once you are back in, review the
[root administrators](/docs/reference/api/root#listadministrators) and repair or remove the lost account. Every run
adds another administrator, so treat it as a break-glass step and alert on `root:recover` events.

```bash
export BETTER_IAM_ROOT_EMAIL=break-glass-2026-09@example.com
export BETTER_IAM_ROOT_PASSWORD="$(cat /run/secrets/break-glass-password)"
better-iam recover-root --config /etc/better-iam/better-iam.config.mjs
```

## doctor

Prints the deployment's health: storage details, audit-chain totals, and configuration and job findings.

- **When:** after every deploy (as a gate with `--strict`), and on a schedule to catch jobs that stopped.
- **Needs:** the database. No credential; it only reads.
- **Fails with:** `DOCTOR_FINDINGS` with `--strict` when any finding is an error or a warning. Without `--strict` it
  exits 0 whenever it can connect, even to a database without the IAM schema.
- **Calls:** [`iam.selfCheck()`](/docs/reference/api#selfcheck).

Flags:

- `--strict` turns error and warning findings into a failing exit. Informational findings never fail.
- `--retention-days N` (0 to 3650, default 30) is the delivery retention your `sweep` runs with, so the sweep backlog
  is judged the same way.

The JSON holds the Node.js version, `rootInitialized` and `rootCount`, `auditChains` and `auditEvents`, `storage`
(adapter, schema version, applied migrations with their times, record counts, and durability settings such as
SQLite's journal mode or PostgreSQL's `synchronous_commit`), `ok`, and `findings`. Each finding has a `check` id, a
`severity`, a `message`, and a `fix`. Errors are a schema behind this release, no root tenant, unsafe SQLite
durability, and stored secrets no configured secret opens. Warnings include an in-memory database, asynchronous
PostgreSQL commits, a placeholder secret, a short metrics token, no email transport, an unfinished secret rotation,
and jobs that are not running (`sweep`, `purge`, `outbox`, audit hooks, and `audit-archive`).

```bash
better-iam doctor --config better-iam.config.mjs --strict --retention-days 14
```

## outbox

Delivers pending email, SMS, and webhook messages, then dispatches queued audit hooks.

- **When:** every minute.
- **Needs:** the delivery callbacks in the configuration (`sendEmail`, `sendSms`). No credential.
- **Calls:** `iam.auth.dispatchOutbox()`, then [`iam.dispatchAuditHooks()`](/docs/reference/api#dispatchaudithooks).

Messages are written to the outbox in the same transaction as the change that caused them and wait there until this
runs. It prints `{ delivered, failed, abandoned }`. A failed attempt is retried with exponential backoff from 30
seconds to one hour and abandoned after `authentication.maxDeliveryAttempts` (default 25). Delivery is at least
once, so transports should deduplicate by message ID.

The audit-hook step reaches plugin `afterAudit` hooks and `events.onEvent` from the configuration file only. Events
it dispatches are marked delivered and never reach subscribers your application registered with
`iam.events.subscribe`, so if you use subscribers, run `iam.auth.dispatchOutbox()` and `iam.events.dispatch()` in
that process instead of this command.

```bash
better-iam outbox --config /etc/better-iam/better-iam.config.mjs
```

## purge

Runs the retention worker: expires ended access and removes tenants deleted more than N days ago.

- **When:** hourly, at least daily.
- **Needs:** no credential. Recorded as `deployment-operator`.
- **Calls:** [`iam.purgeDeleted()`](/docs/reference/api#purgedeleted).

Flags:

- `--retention-days N` (0 to 3650, default 30) is how long a deleted tenant is kept before its records are removed.
  `0` removes deleted tenants on the next run, which cannot be undone.

It disables identities past their scheduled end (`identity:expire`, sessions revoked), deletes expired temporary
bindings, lapsed memberships, ended activations, and package assignments past their end, marks stale access and
package requests expired, removes expired challenges, rate-limit counters, and network blocks, and deletes every
record of tenants tombstoned before the cutoff (one `tenants:purge` event per tenant tree). Audit records always
remain. It prints `purgedTenants`, `deletedRecords`, `expiredBindings`, `expiredRequests`, `expiredIdentities`,
`expiredActivations`, `expiredMemberships`, and `expiredAssignments`, and it is idempotent.

```bash
better-iam purge --config better-iam.config.mjs --retention-days 30
```

## audit-verify

Recomputes one tenant's audit hash chain straight from storage and fails when it does not verify.

- **When:** during an incident or an audit, after restoring a backup, or on a schedule as a tamper check.
- **Needs:** `--tenant`. No credential, and it records nothing.
- **Fails with:** `AUDIT_CHAIN_BROKEN` when an event was edited or removed, or the chain no longer ends at its
  recorded head.

It reads every chained event of the tenant, recomputes each hash and link, compares the end with the chain head, and
prints `{ tenantId, valid, head }` with the position of the first failure. Because it needs no credential and writes
nothing, it is safe to run against production at any time; it holds the whole chain in memory. The API equivalent,
authorized and audited, is [`audit.verify`](/docs/reference/api/audit#verify). See
[audit chain](/docs/guides/events/audit-chain).

```bash
better-iam audit-verify --config better-iam.config.mjs --tenant "$TENANT_ID"
```

## audit-export

Writes one tenant's audit chain to a new JSON Lines file for archiving or outside analysis.

- **When:** on demand (a legal hold or an auditor's request), or before `audit-prune` when you do not use
  `audit-archive`.
- **Needs:** `--tenant` and `--output`. No credential, and it records nothing.
- **Fails with:** a generic failure when the output file already exists; it never overwrites one.

Each line is one chained event in sequence order, exactly as stored with its hashes, so the file can be verified on
its own later with `verifyAuditChain`. It prints `{ tenantId, output, count, firstSequence, lastSequence, head }`;
keep the head with the file as the point the chain must end at. For continuous, verified copies use `audit-archive`.

```bash
better-iam audit-export --config better-iam.config.mjs --tenant "$TENANT_ID" --output "audit-$TENANT_ID-$(date +%F).jsonl"
```

## audit-prune

Deletes one tenant's audit events older than N days and appends a checkpoint so the rest of the chain still verifies.

- **When:** on a schedule that matches your retention policy, after the events were archived or exported.
- **Needs:** `--tenant`. No credential; recorded as `audit:prune` by `deployment-operator`.
- **Calls:** [`iam.pruneAudit()`](/docs/reference/api#pruneaudit).

Flags:

- `--retention-days N` (0 to 36500, default 365) is how old an event must be before it is deleted.

It deletes the oldest events up to the first one newer than the cutoff, in one transaction, and records the sequence
and hash the chain now starts after. With `auditArchive` configured, or once the tenant has an archive cursor, it
never deletes an event the archive does not hold yet, and prints `heldForArchive: true` when it stopped early. It
prints `{ deleted, prunedThroughSequence, prunedThroughHash }`; a rerun with the same retention deletes nothing new.
Deleted events are gone from the database for good, so archive first.

```bash
better-iam audit-prune --config better-iam.config.mjs --tenant "$TENANT_ID" --retention-days 400
```

## config-export

Writes a tenant's access model as a JSON configuration document that `config-plan` and `config-apply` accept.

- **When:** once to bring an existing tenant under version control, then whenever you want a snapshot.
- **Needs:** `--tenant` and `BETTER_IAM_TOKEN`, a session or API key with `iam:config:read`.
- **Fails with:** `MISSING_ENV` without a token; `ACCESS_DENIED` without the permission.
- **Calls:** [`config.export`](/docs/reference/api/config#export).

Flags:

- `--output PATH` writes a new file (never overwriting one) and prints `{ tenantId, output }`. Without it, the
  document goes to standard output.

The document refers to everything by name instead of by ID: tenant-defined resource types, policies, roles, groups
with their members' emails, group bindings, access packages with their automatic-assignment rules, the tenant access
policy, and, when the tenant has any, invariants and agreements. Commit it, review changes as pull requests, and
apply them with `config-apply`. See [configuration as code](/docs/guides/privileged-access/config-as-code).

```bash
BETTER_IAM_TOKEN="$CONFIG_READER_KEY" better-iam config-export --config better-iam.config.mjs --tenant "$TENANT_ID" --output tenant.json
```

## config-plan

Shows the creates, updates, and deletes that applying a configuration file would make, without changing anything.

- **When:** in CI on every change to the file, and nightly to detect drift made in the console.
- **Needs:** `--tenant`, `--input`, and `BETTER_IAM_TOKEN` with `iam:config:read`.
- **Fails with:** `CONFIG_DRIFT` with `--fail-on-drift` when anything would change; `INVALID_INPUT` for an invalid
  document; `MISSING_ENV`; `ACCESS_DENIED`.
- **Calls:** [`config.plan`](/docs/reference/api/config#plan).

Flags:

- `--prune` also plans deletes for the items the file omits, in each kind the file lists. Kinds absent from the file
  are always left alone.
- `--fail-on-drift` exits non-zero, after printing the plan, when it contains any create, update, or delete.

The plan lists every change by kind and name with a `summary` of counts. Use the same `--prune` setting here as in
`config-apply`, so the plan shows exactly what the apply will do.

```bash
BETTER_IAM_TOKEN="$CONFIG_READER_KEY" better-iam config-plan --config better-iam.config.mjs --tenant "$TENANT_ID" --input tenant.json --prune --fail-on-drift
```

## config-apply

Applies a configuration file to a tenant in one transaction.

- **When:** from your deployment pipeline after the plan was reviewed, followed by `check-invariants --fail-on-broken`.
- **Needs:** `--tenant`, `--input`, and `BETTER_IAM_TOKEN` with `iam:config:apply`, plus the permission and grant
  authority for every change it makes.
- **Fails with:** `ACCESS_DENIED` when any single change is not allowed; `SOD_CONFLICT` or `INVARIANT_VIOLATION` when
  the result would break a separation-of-duties rule or an enforced invariant; `INVALID_INPUT` for an invalid
  document; `MISSING_ENV`.
- **Calls:** [`config.apply`](/docs/reference/api/config#apply), audited as `config:apply` with the change summary.

Flags:

- `--prune` deletes items of a listed kind that the file omits. Without it, removing an item from the file does not
  delete it.

Each change is authorized like the equivalent direct API call under the token owner's grant authority, and one
failure rolls the whole apply back, so the tenant never ends up half-configured. It prints the plan it applied. Run
`config-plan` with the same flags first.

```bash
BETTER_IAM_TOKEN="$CONFIG_DEPLOYER_KEY" better-iam config-apply --config better-iam.config.mjs --tenant "$TENANT_ID" --input tenant.json --prune
```

## analyze

Prints a tenant's access-analysis findings as JSON and can fail when serious ones exist.

- **When:** nightly, or as a deployment gate.
- **Needs:** `--tenant` and `BETTER_IAM_TOKEN` with `iam:analysis:read`.
- **Fails with:** `FINDINGS` with `--fail-on` when an unsuppressed finding at or above that severity exists;
  `INVALID_INPUT` for a `--dormant-days` outside 1 to 3650; `MISSING_ENV`; `ACCESS_DENIED`.
- **Calls:** [`analysis.findings`](/docs/reference/api/analysis#findings).

Flags:

- `--dormant-days N` (default 90) is how long an account holding access must go unused before it is reported.
- `--fail-on high|medium|low` exits non-zero when a finding of that severity or higher exists: `high` fails on high
  findings only, `low` on any finding.

Findings cover dormant access, stale keys, policy lint, and separation-of-duties violations (see the
[analysis group](/docs/reference/api/analysis)). Suppressed findings are left out, so suppress accepted risks with
[`analysis.suppress`](/docs/reference/api/analysis#suppress) and the gate stays meaningful.

```bash
BETTER_IAM_TOKEN="$ANALYST_KEY" better-iam analyze --config better-iam.config.mjs --tenant "$TENANT_ID" --dormant-days 60 --fail-on high
```

## report

Prints a tenant's access report: what ends soon, unused API keys, live elevations, and pending requests.

- **When:** nightly, piped into a ticket or a chat channel.
- **Needs:** `--tenant` and `BETTER_IAM_TOKEN` with `iam:identities:read`. The binding and key sections also need
  `iam:bindings:read` and `iam:credentials:read` and are left out without them.
- **Fails with:** `MISSING_ENV`; `ACCESS_DENIED`.
- **Calls:** [`reports.access`](/docs/reference/api/reports#access).

Flags:

- `--within-days N` (0 to 3650, default 30) reports identities and temporary bindings ending within that many days.
- `--unused-days N` (0 to 3650, default 30) reports API keys unused for that many days.

Unlike `digest`, it acts as a member and emails nobody, so use it when the report should go somewhere other than the
owners' inboxes. See [access report](/docs/guides/privileged-access/access-report).

```bash
BETTER_IAM_TOKEN="$REPORTER_KEY" better-iam report --config better-iam.config.mjs --tenant "$TENANT_ID" --within-days 14 | jq '.identities.expiring'
```

## digest

Emails each organization's owners its access report when there is something to report.

- **When:** daily, followed by `outbox`.
- **Needs:** `authentication.sendEmail` in the configuration. No credential; recorded as `tenant:access-digest`.
- **Fails with:** `DELIVERY_REQUIRED` without an email transport.
- **Calls:** [`iam.sendAccessDigest()`](/docs/reference/api#sendaccessdigest).

Flags:

- `--tenant ID` limits the run to one organization (default: every active organization).
- `--within-days N` and `--unused-days N` (each 0 to 3650, default 30) set the report windows, as in `report`.

The owners of each organization with findings receive one `access-digest` email each, with the counts and the full
report as JSON. Organizations with nothing to report, with no owner who has an email address, or already digested in
the last 20 hours are skipped, so a rerun never emails twice. It prints `{ sent, skipped }`.

```bash
better-iam digest --config better-iam.config.mjs --within-days 14 && better-iam outbox --config better-iam.config.mjs
```

## remind

Emails each person whose access ends within N days one reminder listing it.

- **When:** daily, beside `digest`, followed by `outbox`.
- **Needs:** `authentication.sendEmail` in the configuration. No credential; recorded as `identity:expiry-reminder`.
- **Fails with:** `DELIVERY_REQUIRED` without an email transport; `INVALID_ARGUMENT` for `--unused-days`, which
  `remind` does not take.
- **Calls:** [`iam.sendExpiryReminders()`](/docs/reference/api#sendexpiryreminders).

Flags:

- `--tenant ID` limits the run to one organization.
- `--within-days N` (1 to 365, default 7) is how far ahead to look.

It covers the person's own account end date, direct role bindings, temporary group memberships, and access-package
assignments. Each item is reminded once per end date, so reruns are harmless and extended access is reminded again
when its new end comes near. It prints `{ sent, skipped }`.

```bash
better-iam remind --config better-iam.config.mjs --within-days 3
```

## reconcile

Applies access-package rules (birthright access): people who match a rule receive the package, and automatic holders who stopped matching lose it.

- **When:** every 15 minutes, after `purge`.
- **Needs:** no credential and no email transport. Each change runs under the rule owner's grant authority.
- **Fails with:** `RECONCILE_ATTENTION` with `--fail-on-attention` when a change failed, changes were held back, a
  rule is suspended, or an organization could not be processed; `INVALID_ARGUMENT` for `--package` without
  `--tenant` or `--confirm` without `--package`.
- **Calls:** [`iam.reconcilePackages()`](/docs/reference/api#reconcilepackages).

Flags:

- `--tenant ID` limits the run to one organization, and `--package ID` (with `--tenant`) to one package.
- `--confirm` (with `--package`) approves the changes the brake held back for that package and applies them in this
  run.
- `--limit N` (1 to 10000, default 1000) caps the changes per organization per run.
- `--fail-on-attention` exits non-zero when anything needs a person.

SCIM provisioning, invitations, and attribute and group changes take effect in rule-based packages only through this
command. It prints `assigned`, `refreshed`, `restored`, `ending`, `revoked`, `stale`, `failed`, `suspended`,
`braked`, and `truncated`; `truncated: true` means run it again. Scheduled runs hold back unusually large changes
(`braked`) until someone confirms them, so a rule edit or a directory glitch cannot revoke everyone at once. See
[automatic assignment](/docs/guides/privileged-access/automatic-assignment).

```bash
better-iam reconcile --config better-iam.config.mjs --tenant "$TENANT_ID" --package "$PACKAGE_ID" --confirm
```

## close-certifications

Closes every auto-closing certification campaign whose due date has passed and applies its decisions.

- **When:** hourly or daily, with the other jobs.
- **Needs:** no credential. Revocations run under each campaign creator's grant authority; recorded as
  `certification:auto-close`.
- **Calls:** [`iam.closeOverdueCertifications()`](/docs/reference/api#closeoverduecertifications).

Flags:

- `--tenant ID` limits the run to one organization.

Only campaigns created with `autoClose` are touched. Each one closes in its own transaction: revoked bindings are
removed (each audited as `iam:bindings:delete`), and items nobody decided follow the campaign's `undecided` setting.
It prints `{ closed, skipped }`, where `skipped` counts campaigns that are not due yet. See
[certifications](/docs/guides/governance/certifications).

```bash
better-iam close-certifications --config better-iam.config.mjs
```

## mine-roles

Prints role-mining suggestions and peer outliers for a tenant as JSON.

- **When:** weekly, as a snapshot for access reviews.
- **Needs:** `--tenant` and `BETTER_IAM_TOKEN` with `iam:analysis:read`.
- **Fails with:** `INVALID_INPUT` for an identity attribute in `--peer-by` that is not declared; `MISSING_ENV`;
  `ACCESS_DENIED`.
- **Calls:** [`roleMining.suggest`](/docs/reference/api/role-mining#suggest) and
  [`roleMining.outliers`](/docs/reference/api/role-mining#outliers).

Flags:

- `--peer-by manager|attribute:NAME` groups people for outlier detection by shared manager (the default) or by a
  declared identity attribute, such as `attribute:department`.

Suggestions are role bundles to grant as access packages, roles every member of a group holds directly (bind them to
the group instead), direct bindings a group already covers, and duplicate roles. Outliers are roles few peers hold
(access that outlived a move) and roles most peers hold that a person lacks. The command only reads; apply a
suggestion with [`roleMining.apply`](/docs/reference/api/role-mining#apply) or in the console. See
[usage and role mining](/docs/guides/governance/usage-and-mining).

```bash
BETTER_IAM_TOKEN="$ANALYST_KEY" better-iam mine-roles --config better-iam.config.mjs --tenant "$TENANT_ID" --peer-by attribute:department
```

## check-invariants

Evaluates a tenant's access invariants as a member and can fail the build when one is broken.

- **When:** in CI after `config-apply`, and before releases.
- **Needs:** `--tenant` and `BETTER_IAM_TOKEN` with `iam:invariants:read`.
- **Fails with:** `INVARIANTS_BROKEN` with `--fail-on-broken` when an invariant is broken or cannot be evaluated;
  `MISSING_ENV`; `ACCESS_DENIED`.
- **Calls:** [`invariants.run`](/docs/reference/api/invariants#run).

Flags:

- `--fail-on-broken` exits non-zero, after printing the results, when any invariant failed or could not be
  evaluated (its resource or group no longer exists, for example).

It prints `{ generatedAt, summary, results }`, with `passed`, `failed`, and `errors` counts and each invariant's
violators. It records no `invariant:broken` events (that is `monitor-invariants`), so CI can run it as often as it
likes. See [change safety](/docs/guides/governance/change-safety).

```bash
BETTER_IAM_TOKEN="$CI_AUDITOR_KEY" better-iam check-invariants --config better-iam.config.mjs --tenant "$TENANT_ID" --fail-on-broken
```

## monitor-invariants

Evaluates the invariants of every organization and records an audit event whenever one breaks or recovers.

- **When:** hourly, and after configuration changes.
- **Needs:** no credential. Recorded as `deployment-operator`.
- **Calls:** [`iam.checkInvariants()`](/docs/reference/api#checkinvariants).

Flags:

- `--tenant ID` limits the run to one organization.

`invariant:broken` is recorded when an invariant starts failing or gains violators, and `invariant:restored` when it
passes again, once per change, so a webhook subscribed to `invariant:*` alerts without repeating itself. It prints
`{ checked, broken, restored }` and exits 0 whenever it runs: alert from the webhook, or use
`check-invariants --fail-on-broken` when you need a failing exit.

```bash
better-iam monitor-invariants --config better-iam.config.mjs
```

## store-export

Writes every record of the database to a JSON Lines snapshot file.

- **When:** before moving a deployment to another database or adapter, or as a logical backup.
- **Needs:** `--output`. No credential.
- **Fails with:** a generic failure when the output file already exists. On any failure the partial file is removed.

The file holds a header, one line per record, and a trailer with counts. It is read in one transaction, so the
snapshot is consistent, but that transaction holds the write lock until the export finishes, so IAM writes wait
meanwhile. The file is created readable by its owner only and holds password hashes, sessions, and encrypted secrets:
protect it like the database. It prints `{ output, records, collections }`. Load it with `store-import`.

```bash
better-iam store-export --config better-iam.config.mjs --output /secure/backups/better-iam-snapshot.jsonl
```

## store-import

Loads a snapshot into an empty database in one transaction.

- **When:** when moving a deployment to a new database, after `store-export`.
- **Needs:** `--input`, and a configuration whose database holds no IAM records. No credential.
- **Fails with:** `STORE_NOT_EMPTY` when the target already has records; `SNAPSHOT_TRUNCATED` for a file without its
  trailer or with counts that disagree with it; `SNAPSHOT_INVALID` for a corrupt line.

It applies the core schema to the target first (not plugin migrations), then inserts every record verbatim in one
transaction, so any failure leaves the database without records. Records keep their IDs, password hashes, encrypted secrets,
and audit chains, so the target configuration must use the same `secret`. Afterwards run `migrate` with the same
configuration for plugin migrations, and on PostgreSQL run `VACUUM ANALYZE iam_records` so lookups use the index
immediately. See [storage](/docs/operations/storage).

```bash
better-iam store-import --config postgres.config.mjs --input /secure/backups/better-iam-snapshot.jsonl
```

## store-copy

Copies the configured database into the empty database of another configuration in one step, for example from SQLite to PostgreSQL.

- **When:** when moving a deployment between databases or adapters without an intermediate file.
- **Needs:** `--target-config`, naming a different configuration file whose database is empty. No credential.
- **Fails with:** `INVALID_ARGUMENT` when `--target-config` is the same file as `--config`; `SAME_DATABASE` when both
  point at the same database; `STORE_NOT_EMPTY` when the target already has records.

It migrates the target's core schema, reads the source in one transaction, and writes the target in one transaction,
so the copy is consistent and all-or-nothing. Use the same `secret` in both configurations. Then run
`migrate --config` with the target configuration, point the application at it, and on PostgreSQL run
`VACUUM ANALYZE iam_records`.

```bash
better-iam store-copy --config sqlite.config.mjs --target-config postgres.config.mjs
```

## sweep

Deletes expired sessions, devices, relationship tuples, OAuth and SAML artifacts, and old deliveries in short batches.

- **When:** hourly or daily, beside `purge`.
- **Needs:** no credential. Deletions are not audited.
- **Calls:** [`iam.sweepExpired()`](/docs/reference/api#sweepexpired).

Flags:

- `--limit N` (1 to 1,000,000, default 10,000) is the most records one run deletes.
- `--retention-days N` (0 to 3650, default 30) is how long delivered and abandoned outbox messages and failed Shared
  Signals deliveries are kept. Pass the same value to `doctor --retention-days`.

It keeps storage, and scans such as outbox delivery, from growing with traffic. Batches of 500 are deleted in their
own short transactions, so it can run during traffic. API keys, pending deliveries, invitations, access requests,
usage records, and SCIM connections are never deleted by age. It prints `{ deleted, total, truncated }`; when
`truncated` is true more records are due, so run it again or raise `--limit`.

```bash
better-iam sweep --config better-iam.config.mjs --limit 50000 --retention-days 14
```

## rotate-secrets

Re-seals authenticator secrets, webhook secrets, and pending deliveries with the current deployment secret.

- **When:** during a secret rotation, after every process runs with the new `secret` and the old value in
  `previousSecrets` (configurations from `init` read it from `BETTER_IAM_PREVIOUS_SECRETS`, comma-separated).
- **Needs:** no credential.
- **Fails with:** `UNREADABLE_SECRETS`, after printing the result, when stored values open with no configured secret,
  which means the secret that sealed them is missing from `previousSecrets`.
- **Calls:** [`iam.rotateSecrets()`](/docs/reference/api#rotatesecrets).

Flags:

- `--dry-run` only counts what would be re-sealed and changes nothing.

It prints `{ resealed, unreadable, current, complete, done }` and writes in short transactions, so you can stop it
and run it again. Repeat until `done` is true, wait a day for emailed links and assertions issued under the old
secret to expire, then remove `previousSecrets` everywhere. Sessions and API keys do not depend on the secret, so
nobody is signed out. See [rotating the deployment secret](/docs/operations/deployment/secrets).

```bash
better-iam rotate-secrets --config better-iam.config.mjs --dry-run
better-iam rotate-secrets --config better-iam.config.mjs
```

## audit-archive

Copies every tenant's new audit events, verified and in chain order, to the configured `auditArchive`.

- **When:** every few minutes, at least hourly.
- **Needs:** `auditArchive` in the configuration, for example `createJsonlAuditArchive`. No credential.
- **Fails with:** `AUDIT_ARCHIVE_FAILED`, after printing the result, when a tenant's chain did not verify or the sink
  failed or refused a conflicting batch; `NO_AUDIT_ARCHIVE` when no archive is configured.
- **Calls:** [`iam.archiveAudit()`](/docs/reference/api#archiveaudit).

Flags:

- `--tenant ID` archives one tenant only.
- `--limit N` (a positive integer, default 100,000, at most 10,000,000) caps the events archived per run.

It prints `archived` per tenant, `batches`, `failed` (with `AUDIT_CHAIN_BROKEN`, `ARCHIVE_WRITE_FAILED`, or
`ARCHIVE_CONFLICT` per tenant), `gaps`, `busy`, and `truncated`. Overlapping runs are safe: a tenant another run is
archiving is skipped and listed under `busy`. Once archiving runs, `audit-prune` only deletes events the archive
holds. Check the archive on its own with `audit-verify-archive`. See
[continuous audit archiving](/docs/operations/jobs#continuous-audit-archiving).

```bash
better-iam audit-archive --config /etc/better-iam/better-iam.config.mjs
```

## audit-verify-archive

Verifies one tenant's archived audit chain from the archive files alone, without the database.

- **When:** periodically, and before relying on the archive (after an incident, or before discarding database
  backups).
- **Needs:** `--directory` (the directory given to `createJsonlAuditArchive`) and `--tenant`. No configuration,
  database, or credential.
- **Fails with:** `AUDIT_ARCHIVE_INVALID` when a sequence is missing, a hash or link does not recompute, or two
  overlapping files disagree about the same sequence.

Files can overlap after a crash, and each sequence must then carry the identical event. It prints the tenant, the
number of files, the number of conflicts, and the verification result. Because it reads only the files, run it where
the archive lives, for example on the backup host.

```bash
better-iam audit-verify-archive --directory /var/lib/better-iam/audit --tenant "$TENANT_ID"
```

## whoami

Prints who the credential in `BETTER_IAM_TOKEN` acts as, and fails when it is no longer valid.

- **When:** at the start of a CI job or script, to confirm which identity, tenant, and role it runs as, or to check
  that a session, API key, role session, or session token (opaque or JWT) has not been revoked.
- **Needs:** `BETTER_IAM_TOKEN`, or a session saved by `login`. No permission; it records no audit event.
- **Fails with:** `MISSING_ENV` without a token; `SESSION_EXPIRED` when the saved session has ended; `UNAUTHENTICATED`
  when the credential is invalid, expired, or revoked; `INVALID_ARGUMENT` for a flag it does not take (it takes
  `--config`, `--url`, `--profile`, `--format`, and `--query`).
- **Calls:** [`sts.getCallerIdentity`](/docs/reference/api/sts#getcalleridentity).

It prints the identity and its tenant, the tenant the session acts in, the session kind and id, the format, MFA,
issue, sign-in, and expiry times, and, when they apply, the role, trust, source tenant, session name, source identity,
session tags, JWT audiences, web identity, and impersonator. Hashes, policies, and authority ids are never included.

```bash
BETTER_IAM_TOKEN="$ROLE_TOKEN" better-iam whoami --config better-iam.config.mjs | jq '{sessionKind, roleId, expiresAt}'
```

## secret

Prints a new random value for `BETTER_IAM_SECRET`.

- **When:** once per deployment, and again when you rotate the secret (put the old value in
  `BETTER_IAM_PREVIOUS_SECRETS` first; see [secrets](/docs/operations/deployment/secrets)).
- **Needs:** nothing. It reads no configuration and stores nothing.
- **Fails with:** `INVALID_ARGUMENT` for `--bytes` outside 24 to 256.

Flags:

- `--bytes N` sets how many random bytes the secret encodes (default 48, which prints 64 URL-safe characters).
- `--env` prints a `BETTER_IAM_SECRET=value` line for a `.env` file.

The value comes from the operating system's random generator. Treat the output like a password: send it to your
secret store, not to a log.

```bash
better-iam secret --env >> .env
```

## config-validate

Checks a tenant configuration file offline, without a database or a token.

- **When:** in a pre-commit hook and as the first CI step, before `config-plan` needs a token and a network.
- **Needs:** `--input`. No configuration, database, or credential.
- **Fails with:** `INVALID_INPUT` when the document's shape is wrong; `CONFIG_WARNINGS` with `--strict` when it names
  something it does not define.

Flags:

- `--input PATH` is the file: JSON, or a `.mjs`, `.js`, or `.ts` module whose default export is the configuration or
  a factory receiving `{ tenantId, env }`.
- `--tenant ID` is passed to such a factory as `tenantId`.
- `--strict` fails on warnings.

It prints `valid`, a count of items per kind, and `warnings`: each role, binding, package, or invariant that names a
policy, role, or group the file does not define. Those names must already exist in the tenant, or `config-plan` fails.

```bash
better-iam config-validate --input iam/tenant.config.ts --strict
```

## api

Calls any method of the HTTP API as the session or API key and prints the result.

- **When:** for one-off administration from a terminal, and for scripts that need a method no dedicated command covers.
- **Needs:** `BETTER_IAM_TOKEN` or a saved session with the method's own permission; public methods such as
  `tenants.lookup` need none.
- **Fails with:** whatever the method fails with (`ACCESS_DENIED`, `INVALID_INPUT`, `NOT_FOUND` for an unknown
  method); `INVALID_ARGUMENT` for a malformed route or input item; `MISSING_ENV` without a token.
- **Calls:** `POST {basePath}/{group}/{method}`, the same routes and checks as the [HTTP API](/docs/reference/api).

Flags:

- `--data JSON|@FILE|-` gives the whole request body, from the argument, a JSON file, or standard input.
- `key=value` items add fields: `name=Admin` (string), `limit:=10` and `actions:='["a"]'` (JSON),
  `document:=@policy.json` (a JSON file), `content=@terms.md` (a file's text), `resource.type=doc` (nested), and
  `actions[]=read` (append).
- `--tenant ID` fills `tenantId` when the input has none (also `BETTER_IAM_TENANT` or the saved session's tenant).
- `--list [GROUP]` lists every route, or one group's, with whether it needs a credential.

Top-level routes are `authorize`, `authorizeMany`, and `listAccessible`; plugin endpoints are `plugins/{id}/{path}`.
Locally the call has no request-size limit; against `--url` it goes over HTTP like any client.

```bash
better-iam api roles.create name=Reader permissions:='["documents:read"]' --tenant "$TENANT_ID" --query id
```

## can

Checks whether the session or API key may perform an action on a resource.

- **When:** to debug a denial, or in a script that branches on access before it does something.
- **Needs:** `BETTER_IAM_TOKEN` or a saved session, and `--tenant` (or `BETTER_IAM_TENANT`, or the saved session's).
- **Fails with:** `ACCESS_DENIED` when the answer is no (after printing the decision); `INVALID_ARGUMENT` for a resource
  that is not `type/id` or `type:id`.
- **Calls:** [`authorize`](/docs/reference/api#authorize).

It prints the decision with its reason and exits 0 only when allowed, so `if better-iam can …; then` works. The check
is recorded like any other authorization decision.

```bash
better-iam can documents:write document/d1 --tenant "$TENANT_ID"
```

## explain

Shows why another identity would be allowed or denied an action, without signing in as them.

- **When:** when someone reports a denial, or before granting access, to see which statement decides.
- **Needs:** a token with `iam:policies:simulate`, `--tenant`, and `--identity` (an ID or an email).
- **Fails with:** `NOT_FOUND` when no single identity has the email; `ACCESS_DENIED`.
- **Calls:** [`policies.simulate`](/docs/reference/api/policies#simulate).

Flags:

- `--identity ID|EMAIL` is the person or service account to explain.
- `--assume-mfa` evaluates as if they had signed in with MFA.

```bash
better-iam explain documents:write document/d1 --identity alice@acme.test --tenant "$TENANT_ID"
```

## who-can

Lists every active identity that could perform an action on a resource, with the reason.

- **When:** in access reviews and audits, and before deleting or sharing a sensitive resource.
- **Needs:** a token with `iam:policies:simulate` and `--tenant`.
- **Fails with:** `INVALID_ACTION` for an action the catalog does not know; `ACCESS_DENIED`.
- **Calls:** [`policies.whoCan`](/docs/reference/api/policies#whocan).

Flags:

- `--kind user|service` lists only people or only service accounts.
- `--assume-mfa` evaluates everyone as if signed in with MFA.
- `--limit N` caps the list (default 100).

Root administrators are not listed: their override applies everywhere.

```bash
better-iam who-can documents:delete document/d1 --tenant "$TENANT_ID" --format table
```

## login

Signs in once and saves the session, so later member commands need no `BETTER_IAM_TOKEN`.

- **When:** at the start of a terminal session against a deployment, or once per CI job with `--with-token`.
- **Needs:** `--tenant` or `--org`, `--email` (or a prompt), and the password from `BETTER_IAM_PASSWORD` or a hidden
  prompt; the MFA code from `BETTER_IAM_MFA_CODE` or a prompt.
- **Fails with:** `INVALID_CREDENTIALS`; `MFA_ENROLLMENT_REQUIRED` when the account must enroll an authenticator first;
  `MISSING_ENV` when there is no password and no terminal to ask in; `PROFILE_IN_USE` when the profile holds a session
  for another deployment.
- **Calls:** [`auth.signIn`](/docs/reference/api/auth#signin), then `auth.verifyMfa` and
  [`sts.getCallerIdentity`](/docs/reference/api/sts#getcalleridentity).

Flags:

- `--url URL` signs in to a running server; without it, the session is issued through the configuration.
- `--tenant ID` or `--org SLUG` names the organization.
- `--email-code` has a one-time code emailed instead of using an authenticator, when the organization allows it.
- `--with-token` saves a token read from standard input (an API key, or a session from elsewhere) after checking it.
- `--profile NAME` saves under that name (default: the current profile, or `default`) and makes it current. Without
  it, `login` refuses with `PROFILE_IN_USE` to replace a profile that holds a session for another deployment.

A saved session is only ever used with the deployment that issued it: with `--url` or `--config` naming another one,
member commands fail with `MISSING_ENV` and say which deployment the session belongs to. `--url` must use `https://`
except for `localhost`.

The session is saved in `~/.config/better-iam/credentials.json` (`%APPDATA%\better-iam\credentials.json` on Windows, or
`BETTER_IAM_CREDENTIALS`) with owner-only permissions, together with the server or configuration and the tenant, so
later commands need neither `--url` nor `--tenant`. Passwords and codes never appear in arguments or in the file.

```bash
echo "$CI_API_KEY" | better-iam login --with-token --url https://iam.example.com --profile ci
```

## logout

Signs a saved session out on the server and forgets it.

- **When:** when you are done with a deployment, or to replace a session.
- **Needs:** a saved profile (`--profile`, default the current one).
- **Fails with:** `NOT_FOUND` when no profile has that name.
- **Calls:** [`auth.signOut`](/docs/reference/api/auth#signout) for user sessions.

API keys and other machine credentials saved with `--with-token` are only forgotten, never revoked. The profile is
removed even when the session had already ended.

```bash
better-iam logout --profile ci
```

## profiles

Lists the sessions saved by `login`, or chooses or removes one.

- **When:** to see which identity and deployment commands will act as, or to switch between them.
- **Needs:** nothing; it never prints tokens.
- **Fails with:** `NOT_FOUND` for an unknown profile; `INVALID_ARGUMENT` for a name with other characters than
  letters, digits, dot, dash, and underscore.

`profiles` prints a table of names, servers or configurations, tenants, identities, and expiry, marking the current
profile; `profiles use NAME` makes one current, and `profiles remove NAME` forgets one without signing it out. For a
single command, `--profile NAME` or `BETTER_IAM_PROFILE` picks another profile, and `BETTER_IAM_TOKEN` bypasses
profiles entirely.

```bash
better-iam profiles use staging
```

## token

Prints the token member commands would act as, for other tools and scripts.

- **When:** to hand the saved session to a tool that reads `BETTER_IAM_TOKEN` or an `Authorization` header.
- **Needs:** `BETTER_IAM_TOKEN` or a saved session.
- **Fails with:** `MISSING_ENV` without either; `SESSION_EXPIRED` when the saved session has ended.

The output is a credential: keep it out of logs and shell history.

```bash
export BETTER_IAM_TOKEN="$(better-iam token)"
```

## completion

Prints a shell completion script for every command, flag, and fixed flag value.

- **When:** once, from your shell profile.
- **Needs:** nothing; project commands from a configuration it finds are included.
- **Fails with:** `INVALID_ARGUMENT` for a shell other than `bash`, `zsh`, `fish`, or `powershell`.

```bash
eval "$(better-iam completion bash)"
```
## billing-close

Issues billing statements for a month that has ended and deletes raw usage events past their retention.

- **When:** daily; accounts already invoiced for the month are skipped, so repeated runs are safe.
- **Needs:** no credential. Each statement is recorded as `billing:statement`; with `authentication.sendEmail` it is
  emailed to the account's billing emails (or owners) as `billing-statement`.
- **Fails with:** `INVALID_INPUT` for the current or a future month.
- **Calls:** `iam.billing.closePeriod()`.

Flags:

- `--period YYYY-MM` is the month to close (default: last month).
- `--tenant ID` closes only the billing account that pays for that tenant.
- `--draft` keeps the invoices as drafts, refreshed on every run, until finalized (also the default with the option
  `billing.autoFinalize: false`).

Each account with something to bill (usage of meters defined above it, subscription fees and seats, pending invoice
items) gets one invoice with its lines, coupons, credit applied earliest expiry first, and a breakdown of usage by
project, team, department and person. See [billing](/docs/reference/api/billing).

## billing-reminders

Reminds billing contacts of unpaid invoices before and after their due date.

- **When:** daily.
- **Needs:** no credential. Each reminder is recorded as `billing:payment-reminder`; with `authentication.sendEmail` it
  is emailed to the invoice's billing emails as `payment-reminder`.
- **Calls:** `iam.billing.sendPaymentReminders()`.

Reminders go out at each step of the `billing.paymentReminderDays` option (default 3 days before the due date, on it,
and 7 and 14 days after), once per step; a step missed while the job did not run is skipped for the latest one reached.
Paid, void and uncollectible invoices get none.

## billing-alerts

Checks every spend budget and sends alerts for thresholds reached and projections past the budget.

- **When:** hourly.
- **Needs:** no credential. Alerts are recorded as `billing:budget-alert` (forward them with a webhook) and emailed as
  `spend-alert` when mail is configured.
- **Calls:** `iam.billing.checkBudgets()`.

Flags:

- `--tenant ID` checks only the budgets that tenant owns.

Each threshold alerts once per budget window (a month, quarter or year), and the forecast alert once when the linear
projection passes 100%.

## billing-seats

Records one seat for every active person of every tenant a seats meter reaches, once per day.

- **When:** daily.
- **Needs:** no credential, and a meter with the key (`seats` by default) defined by the platform or an organization.
- **Calls:** `iam.billing.recordSeats()`.

Flags:

- `--meter KEY` is the meter to record on (default `seats`).
- `--tenant ID` limits the run to that tenant and the tenants below it.
- `--include-service-accounts` counts service accounts and agents as seats too.

A `sum` meter then counts seat-days and a `unique` meter active seats per month; each seat is attributed to its person,
their teams and department. Tenants the meter does not reach are counted under `skippedTenants`.

## spend

Prints the spend of a tenant and the tenants below it for a month.

- **When:** for finance exports and scripts, or to check a team's spend from a terminal.
- **Needs:** `BETTER_IAM_TOKEN` with `iam:billing:read` in the tenant.
- **Fails with:** `INVALID_ARGUMENT` for an unknown `--group-by`; `NOT_FOUND` for a team, department or identity
  outside the tenant.

Flags:

- `--tenant ID` (or `BETTER_IAM_TENANT`) is the tenant to report on.
- `--period YYYY-MM` is the month (default: the current one, with a forecast).
- `--group-by meter|identity|agent|team|department|tenant|day` (default `meter`).
- `--team ID`, `--department ID`, `--identity ID` and `--meter KEY` narrow the report.

```bash
better-iam spend --tenant "$ACME" --group-by team --format table
```

## billing-anomalies

Checks every billing account for spend spikes and alerts on each once.

- **When:** daily, shortly after midnight in the billing time zone.
- **Needs:** no credential. Each spike is recorded as `billing:anomaly`; with `authentication.sendEmail` each account's
  billing emails (or owners) get one `spend-anomaly` email listing the largest five.
- **Fails with:** `INVALID_INPUT` for a malformed `--day`.
- **Calls:** `iam.billing.detectAnomalies()`.

Flags:

- `--day YYYY-MM-DD` is the day to check (default: yesterday).
- `--factor N` (2 to 1000, default 3) is how many times the usual daily spend counts as a spike.
- `--minimum N` (default 10) is the smallest spend and increase worth reporting, in currency units.
- `--tenant ID` checks only the billing account that pays for that tenant.

A person, team or meter counts as spiking when its spend on the day is at least the factor times its average over
the 14 days before and at least the minimum more; new spending counts when it reaches the minimum.
