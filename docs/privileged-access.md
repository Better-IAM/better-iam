# Privileged access and access lifecycle

This guide ties together the features that keep standing privilege low and access time-bound: eligible roles that members activate just in time (with justification, MFA, approval, and windows), scheduled deactivation of identities, API key hygiene, offboarding, the access report, and configuration as code. The API details live in [policies](policies.md) and the copy-ready calls in [recipes](recipes.md); this page explains how the pieces fit.

## Standing versus eligible roles

A role binding is _standing_ by default: the role applies whenever the binding is live. Two properties make a binding narrower without changing the role:

- `startsAt` future-dates it: the binding is visible with its start but grants nothing until then (access that begins on the first day of a contract).
- `expiresAt` makes it temporary. It stops granting at that instant and the purge worker removes it. Group memberships can carry an `expiresAt` too, which ends every grant and activation the membership carried.
- `window` (`{ from, to, timeZone, days? }`) makes it recurring: the binding applies only inside business hours in the named time zone.

An _eligible_ binding (`eligible: true`) goes further: it grants nothing until the member activates it through `bindings.activate`, and then only for a bounded time (`maxActivationMs`, one hour by default, seven days at most). Eligibility is the tool for administrator, auditor, incident-response, and production-access roles: the person is entitled to the role, but holds it only while they need it, and every activation leaves a record with a reason.

Activation rules are set per binding:

| Rule                   | Effect                                                                                           |
| ---------------------- | ------------------------------------------------------------------------------------------------ |
| `requireJustification` | The activation must state a reason; it is stored on the activation and in the audit trail.       |
| `requireMfa`           | Only an MFA-verified session may activate.                                                       |
| `requireApproval`      | Activation becomes a request that an approver grants or denies; nobody approves their own.       |
| `approverGroupId`      | Only members of this group (or root) may decide, and they are emailed each request.              |
| `maxActivationMs`      | The longest activation a member may ask for; approvers may shorten a request, never lengthen it. |

Members see what they may activate with `bindings.listMine` and administrators see the state of everything with `bindings.listActivations` and `identities.listBindings` (which reports `activation`, `pendingActivation`, and `inWindow`). The console's Elevate page is the member's view: eligible roles with their rules, the activation form, pending requests, and, for approvers, the requests awaiting their decision.

An organization can also set floors for every eligible binding at once with `tenants.setAccessPolicy` (console: "Elevation defaults" on the Configuration page): a cap on activation length, mandatory justification, MFA, or approval, and how long requests wait for a decision. A binding can be stricter than the policy, never looser, so adopting a floor later tightens existing bindings without editing them.

## Who may activate and approve

Every person can carry a manager (`identities.create` or `update` with `managerId`; the member page shows the manager and, through `identities.listReports`, their reports). An eligible binding or an access package with `managerApproval` routes requests to the requester's manager, who is emailed and may decide, alongside an approver group if one is named too; offboarding hands a manager's reports to the successor.

Activation and approval are ordinary permissions, so a tenant decides who elevates and who approves through roles:

- `iam:bindings:activate` on `iam/{roleId}` lets a member activate an eligible binding of that role; on `*` it lets them activate any role they are eligible for, and on the tenant it also serves `bindings.listMine`.
- `iam:bindings:approve` on `iam/{roleId}` lets a person decide requests for that role; on the tenant it also serves `bindings.listApprovals`.

The usual shape is a _Member_ role bound to a group every person belongs to (`permissions: ['iam:bindings:activate']`) and an _Approver_ role bound to the approver group. Because a member cannot approve their own request and an approver group can be named on the binding, approval gives you two-person control for the roles that need it.

## Audit and alerting

Every step is recorded: `binding:activate`, `binding:activation-requested`, `binding:activation-approved`, `binding:activation-denied`, and `binding:deactivate` (with `cancelled: true` for withdrawn requests and `revoked: true` when an administrator ended an activation). Subscribe a webhook to `binding:*` to alert on elevation, or query the audit log for a member's history; the member page in the console shows it as "Activation history".

When the deployment sends email, approver-group members receive `activation-request` and requesters receive `activation-decided`; both templates carry the activation, role, requester, justification, and decision so an application can render them however it likes.

## Time-bound identities

People and service accounts can carry a deadline (`expiresAt` on `identities.create`, `identities.update`, `serviceAccounts.create`, `serviceAccounts.update`). Past it, every credential of the identity is refused, and the retention worker (`purgeDeleted`) disables the identity, revokes its sessions, and records `identity:expire`. `identities.list({ expiresBefore })` and the access report show what ends soon; clearing or extending the deadline is the only way to re-enable an expired identity, so nobody quietly turns a contractor back on.

## API keys

Keys carry a `name` and `description`, record `lastUsedAt` when they authenticate a request, and can be issued with `scopes` (an action allowlist compiled into a session policy) so an integration never holds more than it needs. `credentials.list({ unusedForMs })` finds keys nobody uses; rotation keeps the label and expiry but resets the usage history, so a rotated key shows up as unused until it is put to work.

## Offboarding

`identities.offboard` disables a person or service account and removes everything that granted them access in one transaction: sessions and keys, role bindings, group memberships, activations, relationships, pending access requests, and the grant authorities they held, transferring ownership of managed resources to a successor. The identity stays as a disabled record for retention and can be tombstoned later with `identities.delete`. The console offers it on the member page.

## The access report

`reports.access` (console: Reports; CLI: `better-iam report --tenant ID`) gathers the lifecycle state in one document: identities and temporary bindings ending within a window, live activations, pending requests, and keys unused or ending soon. Sections the caller may not read are omitted rather than failing, so a directory administrator without `iam:credentials:read` still gets the identity section. Run it nightly and route it to a channel, or wire it into a ticketing system. `iam.sendAccessDigest` (CLI `digest`) does the routing for you: every organization whose report has findings gets it emailed to its owners, at most once a day. `iam.sendExpiryReminders` (CLI `remind`) tells the people themselves: one email listing their account, role bindings, group memberships, and packages that end within a week, once per item.

## Configuration as code

Roles (including inheritance), policies, groups with their members, tenant-defined resource types, and group bindings with every activation rule and window can be exported (`config.export`), planned (`config.plan`), and applied (`config.apply`) as one JSON document keyed by name. Keep the document in version control, review changes as pull requests, apply the same file to staging and production, and let `config-plan --fail-on-drift` fail a pipeline when someone changed production by hand. Identities and their direct bindings are runtime state and stay out of the document.

## Access packages

Standing access that always comes as a set (a new engineer gets the Reader role and the Engineering group; a contractor gets a vendor profile for the length of the contract) is an access package: `packages.assign` grants every role and group in it as ordinary, time-bound bindings and memberships in one transaction, and `packages.revoke` or the expiry takes exactly that set away again. A package with `maxDurationMs` forces an end date, `requireJustification` records why, and the assigner still needs the right to grant each part, so a package is a convenience for administrators and reviewers, never a bypass. Mark a package `requestable` with an approver group and members ask for it themselves (`packages.request`, from the Elevate page); the approvers are emailed, decide from the same page, and the approval assigns the package under their authority. The console lists packages, their holders, and the requests on the Access packages page.

## Putting it together

A common baseline for an organization:

1. Everyone is in an _Everyone_ group that holds `iam:bindings:activate`; nobody holds a standing administrator role.
2. Administrator and production roles are bound to the relevant groups as eligible, with `requireJustification`, `requireMfa`, and (for the most sensitive) `requireApproval` with a named approver group.
3. Contractors get an `expiresAt`; integrations get scoped, labeled keys.
4. A nightly job runs `purgeDeleted`, `report`, and `config-plan --fail-on-drift`.
5. Leavers go through `identities.offboard` with a successor for the resources they owned.
