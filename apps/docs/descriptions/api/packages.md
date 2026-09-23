# packages

Access packages bundle roles and group memberships that are granted, requested, and removed together. An
onboarding kit, a project profile, or a vendor's access becomes one named package instead of a checklist of
separate grants, and removing it takes away exactly what it gave. See the
[access packages guide](/docs/guides/privileged-access/access-packages) for a walkthrough.

## How packages are granted

A package can reach a person in three ways, and one package can use all of them:

- **Assignment.** An administrator calls `assign`. The caller needs `iam:packages:assign` on the package plus
  everything the direct calls need: `iam:bindings:create` on each role and `iam:groups:update` on each group. The
  records are created under the caller's own [grant authority](/docs/guides/authorization/roles#grant-authorities),
  so a package never lets anyone grant more than they could grant by hand.
- **Self-service request.** When the package is `requestable`, a member holding `iam:packages:request` on it asks
  for it with `request`, and an approver decides with `approveRequest` or `denyRequest`. Who may approve depends on
  the package: with neither `approverGroupId` nor `managerApproval`, anyone holding `iam:packages:approve` on the
  package; otherwise only live members of the approver group, the requester's manager (with `managerApproval`), or
  a root administrator. Nobody decides on their own request, and never from an
  [impersonation](/docs/guides/authentication/impersonation) session. Approval assigns the package under the
  approver's authority, so the approver needs the same rights as `assign`. A request waits for the tenant's
  `approvalLifetimeMs` (one day by default, set with
  [`tenants.setAccessPolicy`](/docs/reference/api/tenants#setaccesspolicy)), never beyond the end it asks for.
- **Rule (birthright).** A package with an `autoAssign` rule is given to every active identity that matches the
  rule and taken back from automatic holders that stop matching. A reconciler applies the rule under the grant
  authority of the rule's owner (whoever last saved the rule or changed the package's contents). It runs after
  identity changes and rule saves, on demand with `reconcile`, and as the scheduled job
  [`iam.reconcilePackages()`](/docs/reference/api#reconcilepackages), which you must schedule. See
  [automatic assignment](/docs/guides/privileged-access/automatic-assignment) for the rule language, grace
  periods, and the safety brake.

`maxDurationMs` makes an end date mandatory for assignments and requests and caps it; `requireJustification` makes
the justification mandatory. A rule package cannot have `maxDurationMs` (use the rule's `graceMs` for a delayed
end), and its automatic assignments satisfy `requireJustification` with "Automatic: matches the package rule".

## What an assignment owns

An assignment turns every packaged role into an identity binding of its own and every packaged group into a
membership, all ending at the assignment's `expiresAt`. Each record is tagged with the assignment. Because the
bindings are the assignment's own, a package never depends on, replaces, or removes a binding someone granted by
hand. A group has one membership record per person, so memberships are shared:

- A membership the person already holds for at least as long is left alone and reported in `skipped`.
- A shorter membership is extended and becomes the assignment's.
- When two of a person's packages include the same group, the membership belongs to whichever needs it longest and
  passes to the other when that one is revoked or shortened.

Revoking removes exactly the records the assignment still owns, together with any just-in-time activations they
carried, then the assignment itself. Editing one of its records by hand (`bindings.update`, `groups.updateMember`,
re-adding a lapsed member) takes that record over, so revoking the package no longer removes it. An assignment ends
by itself at `expiresAt`: it stops granting at once, and the purge worker (`iam.purgeDeleted()`) deletes it with
its records later. An assignment whose bindings no longer grant, for example because the assigner was offboarded
and their authority revoked, is reported as `broken`; assign or request the package again to replace it.

Offboarding an identity revokes its assignments and cancels its pending requests; deleting it removes both. A role
or group cannot be deleted while a package includes it.

## approveRequest

Grants a pending package request by assigning the package to the requester under your own authority.

- **Permission:** `iam:packages:approve` on the package; when the package names approvers, membership of the
  approver group or being the requester's manager (or root); plus the rights `assign` needs for every role and group.
- **Audited as:** `iam:packages:approve`, plus `package:request-approved` with the assignment's counts, skips, and end.
- **Errors:** `INVALID_TRANSITION` when the request is no longer pending or the package is no longer requestable;
  `NOT_FOUND` when the request is not in this tenant; `INVALID_INPUT` for your own request or an end the package
  does not allow; `ACCESS_DENIED`
  when you are not a designated approver or cannot grant one of the packaged roles or groups;
  `IMPERSONATION_RESTRICTED` from an impersonation session; `GRANT_AUTHORITY_REQUIRED` without a grant authority;
  `SOD_CONFLICT` when the assignment would create a [separation-of-duties](/docs/guides/authorization/separation-of-duties)
  conflict; `INVARIANT_VIOLATION` when it would break an enforced invariant.

The assignment ends at the `expiresAt` you pass or, without it, at the end the requester asked for, validated
against the package's `maxDurationMs`. The optional `note` is stored on the request. When the deployment sends
email, the requester receives a `package-decided` message.

```ts
await iam.api.packages.approveRequest(credential, {
  tenantId,
  requestId,
  expiresAt: Date.now() + 14 * 24 * 60 * 60 * 1000, // shorter than the 30 days they asked for
  note: 'Two weeks covers the migration.',
});
```

## assign

Grants a package to a person: one binding per role and one membership per group, all ending together.

- **Permission:** `iam:packages:assign` on the package, `iam:bindings:create` on each packaged role,
  `iam:groups:update` on each packaged group, and authority over the role bindings of each group the person joins.
- **Audited as:** `iam:packages:assign`, plus `package:assign` with the created counts, `skipped`, end, and
  justification.
- **Errors:** `CONFLICT` when the person already holds a manual assignment of the package that is not broken;
  `NOT_FOUND`
  when the package or person is not in this tenant or the person is deleted; `INVALID_INPUT` when an end is
  required and missing, exceeds `maxDurationMs`, or a required justification is missing; `ACCESS_DENIED` without
  the rights for one of the parts; `GRANT_AUTHORITY_REQUIRED` without a grant authority; `SOD_CONFLICT` and
  `INVARIANT_VIOLATION` when the grant would create a conflict or break an enforced invariant.

Everything happens in one transaction, so either the whole package is granted or nothing is. The result carries the
assignment, `created` (bindings and memberships), `skipped` (memberships the person already held for as long), and
`replacedAutomatic`. Assigning a package the person holds through its rule takes the automatic assignment over: it
becomes a manual one under your authority. Assigning also marks the person's pending request for the package as
approved.

```ts
const result = await iam.api.packages.assign(credential, {
  tenantId,
  packageId,
  identityId,
  expiresAt: Date.now() + 90 * 24 * 60 * 60 * 1000,
  justification: 'Joins the Atlas project for Q4',
});
// result.created: { bindings: 2, memberships: 1 }, result.skipped: [...]
```

## cancelRequest

Withdraws one of your own pending package requests.

- **Permission:** `iam:packages:request` on the package, and you must be the requester.
- **Audited as:** `iam:packages:request`, plus `package:request-cancelled`.
- **Errors:** `ACCESS_DENIED` when the request is someone else's; `INVALID_TRANSITION` when it is no longer pending;
  `NOT_FOUND` when the request is not in this tenant.

## create

Defines a package of roles and groups, optionally requestable or assigned automatically by a rule.

- **Permission:** `iam:packages:create` on the tenant. With `autoAssign`, also `iam:packages:assign` on the package
  and every right `assign` needs, including authority over the packaged groups' bindings.
- **Audited as:** `iam:packages:create`, plus `package:auto-rule` when a rule is set.
- **Errors:** `CONFLICT` when a package with the same name (ignoring case) exists; `INVALID_INPUT` when it has no
  role or group, more than 50 of either, a `maxDurationMs` outside one minute to ten years, or a rule that does not
  validate; `PROTECTED_RESOURCE` for a protected (owner) role; `NOT_FOUND` when a role, group, or approver group is
  not in this tenant; `INVALID_POLICY` when a rule clause is not a valid condition block. With a rule, also
  `IMPERSONATION_RESTRICTED`, `ACCESS_DENIED`, and `GRANT_AUTHORITY_REQUIRED` from the owner checks.

A new package without a rule grants nothing until you assign it or someone requests it. With `autoAssign` you
become the rule's owner, and the rule must be set from an ordinary session or API key, never an assumed role. After
the save commits, a first reconcile of up to 200 changes runs and its result is returned as `reconcile`; if it
fails, the call still succeeds and the scheduled job catches up. The save also pre-approves the rule's planned counts
for a day, so scheduled runs in that window apply the rest without the safety brake holding them back.

```ts
// Everyone in engineering (people, not service accounts) gets the kit automatically.
const pkg = await iam.api.packages.create(credential, {
  tenantId,
  name: 'Engineering onboarding',
  roleIds: [developerRole.id],
  groupIds: [engineeringGroup.id],
  autoAssign: {
    include: [{ StringEquals: { 'principal.kind': 'user', 'principal.department': 'engineering' } }],
    graceMs: 7 * 24 * 60 * 60 * 1000,
  },
});
// pkg.reconcile?.assigned: how many people received it right away
```

## delete

Deletes a package nobody holds, together with its request history.

- **Permission:** `iam:packages:delete` on the package.
- **Audited as:** `iam:packages:delete`.
- **Errors:** `RESOURCE_IN_USE` (409) while any live assignment exists; `NOT_FOUND` when the package is not in this
  tenant.

Revoke manual assignments first. For a rule package, set `autoAssign` to `null` with `update` so reconciliation
removes the automatic assignments, then delete. Ended assignments, requests, and rule issues are deleted with the
package.

## denyRequest

Refuses a pending package request, with an optional note to the requester.

- **Permission:** `iam:packages:approve` on the package and, when the package names approvers, membership of the
  approver group or being the requester's manager (or root).
- **Audited as:** `iam:packages:approve`, plus `package:request-denied`.
- **Errors:** `INVALID_TRANSITION` when the request is no longer pending; `NOT_FOUND` when the request is not in
  this tenant; `INVALID_INPUT` for your own request; `ACCESS_DENIED` when you are not a designated approver;
  `IMPERSONATION_RESTRICTED` from an impersonation session.

Denying needs no grant rights, since nothing is granted. When the deployment sends email, the requester receives a
`package-decided` message with your note.

## extend

Moves the end of a person's manual assignment, for the assignment and every record it created at once.

- **Permission:** `iam:packages:assign` on the package. Lengthening, or `expiresAt: null`, is granting: it also
  needs the rights `assign` needs and a grant authority.
- **Audited as:** `iam:packages:assign`, plus `package:extend` with the previous and new end.
- **Errors:** `NOT_FOUND` when the person holds no live assignment of the package; `INVALID_TRANSITION` for an
  automatic assignment; `INVALID_INPUT` when `expiresAt` is missing or the new end breaks the package's
  `maxDurationMs` (including `null` on a capped package); `ACCESS_DENIED` or `GRANT_AUTHORITY_REQUIRED` when
  lengthening without the rights.

Shortening needs no more than revoking does. When you lengthen, the assignment's bindings move to your authority, so
the longer grant is bounded by what you may give. Shortening a shared membership hands it to another of the person's
packages that still needs it longer. Automatic assignments end when the person stops matching the rule; assign the
package manually to take one over and set an end.

```ts
await iam.api.packages.extend(credential, { tenantId, packageId, identityId, expiresAt: Date.parse('2026-12-31') });
```

## get

Returns one package with its live holder counts and, for a rule package, the rule's state.

- **Permission:** `iam:packages:read` on the package.
- **Audited as:** `iam:packages:read`.
- **Errors:** `NOT_FOUND` when the package is not in this tenant.

`assignments` counts live holders and `automaticAssignments` those the rule assigned. A rule package also returns
`autoAssign` with the owner's name, `status` (`active` or `suspended`, with the reason), advice in `warnings`, and
the 20 newest problems in `issues`.

## list

Lists the tenant's packages by name, each with its live holder counts.

- **Permission:** `iam:packages:read` on the tenant.
- **Audited as:** `iam:packages:read`.

## listApprovals

Lists the pending package requests you may decide on.

- **Permission:** `iam:packages:approve` on the tenant.
- **Audited as:** `iam:packages:approve`.

Use it for an approver's inbox. Each request is included only when its package is still requestable, you hold
`iam:packages:approve` on that package, you satisfy the package's approver rules, and the request is not your own.

## listAssignments

Lists the holders of a package, or the packages of a person, newest first.

- **Permission:** `iam:packages:read` on the package when you pass `packageId`, otherwise on the tenant.
- **Audited as:** `iam:packages:read`.
- **Errors:** `NOT_FOUND` when `packageId` is not in this tenant; `INVALID_INPUT` when `source` is not `automatic`
  or `manual`.

Ended assignments are included only with `includeExpired: true`. Each entry names the package and person and
reports `expired`, `broken` (its bindings no longer grant), and `automatic` (assigned by the rule).

## listMine

Returns your self-service view: the requestable packages with your status on each, your assignments, and your recent requests.

- **Permission:** `iam:packages:request` on the tenant.
- **Audited as:** `iam:packages:request`.

Each requestable package comes with its roles and groups named, the approver group's name, and your live
`assignment` or `pending` request, which is enough to render "held", "awaiting approval", or "request". A package's
rule is never shown here. `requests` holds your 50 most recent requests. Every requestable package is listed, even
one you lack `iam:packages:request` on, so `request` can still refuse it.

## listRequests

Lists package requests for a package or a person, newest first, optionally by status.

- **Permission:** `iam:packages:read` on the package when you pass `packageId`, otherwise on the tenant.
- **Audited as:** `iam:packages:read`.
- **Errors:** `INVALID_INPUT` for an unknown `status`; `NOT_FOUND` when `packageId` is not in this tenant.

A pending request past its lapse time is reported, and filtered, as `expired` even before the purge worker marks it.

## previewAutoAssign

Shows what a package rule matches and, for a package, what a reconcile would change, without writing anything.

- **Permission:** `iam:packages:read` on the package (or the tenant without `packageId`), plus `iam:identities:read`
  on the tenant to evaluate a rule.
- **Audited as:** `iam:packages:read`.
- **Errors:** `INVALID_INPUT` or `INVALID_POLICY` for a candidate rule that does not validate; `ACCESS_DENIED`
  without `iam:identities:read`; `NOT_FOUND` when `packageId` is not in this tenant.

Pass a candidate `autoAssign` to test a rule before saving it, `packageId` alone to inspect the stored rule, or
neither to get only `keys`, the attribute keys a rule may test with their operators. The result counts `matching`,
`excluded`, and `frozen` (disabled or expired) identities and lists a `sample` of matches (20 by default, at most
100). With `packageId` it adds the `plan` (how many would be assigned, refreshed, restored, ended, or revoked), the
first changes, whether the `brake` would hold them back, and the rule's current `status`. `warnings` flags clauses
that also match service accounts or accept unverified email addresses.

```ts
const preview = await iam.api.packages.previewAutoAssign(credential, {
  tenantId,
  packageId,
  autoAssign: {
    include: [
      {
        StringEqualsIgnoreCase: { 'identity.emailDomain': 'acme.com' },
        Bool: { 'identity.emailVerified': true },
        StringEquals: { 'principal.kind': 'user' },
      },
    ],
  },
});
// preview.plan: { assign, refresh, restore, ending, revoke, manual, keep }
// preview.brake.grants.trips: true when a scheduled run would hold the grants back
```

## reconcile

Runs the package-rule reconciler now for the tenant or one package, optionally confirming held-back changes.

- **Permission:** `iam:packages:assign` on the package (or the tenant without `packageId`). `confirm: true` also
  needs the rights to assign the package by hand.
- **Audited as:** `iam:packages:assign`; each change as `package:auto-assign`, `package:auto-ending`, or
  `package:auto-revoke`, and problems as `package:auto-failed`, `package:auto-suspended`, or `package:auto-braked`,
  all by `deployment-operator`; a confirmation as `package:auto-confirm` by you.
- **Errors:** `INVALID_INPUT` when `confirm` is given without `packageId` or `limit` is outside 1 to 10000;
  `INVALID_TRANSITION` when confirming a package that has no rule; `ACCESS_DENIED` or `GRANT_AUTHORITY_REQUIRED` when
  confirming without the rights.

Use it after a bulk import or a configuration apply (which does not reconcile), or to apply changes the brake held
back. Without `packageId` it covers every rule package in the tenant, plus packages whose rule was cleared but that
still have automatic holders. Removals run first, then additions, each change in its own transaction, at most
`limit` changes (1000 by default).
Without `confirm`, a run holds back more than the rule's `maxGrants` (100) new grants or `maxRemovals` (25) removals
per package and reports them in `braked`. `confirm: true` approves the package's planned counts for a day and applies
them in this run. Failures for one person, such as a separation-of-duties conflict, are reported in `failed` and
never stop the run; `truncated: true` means the budget ran out, so run again.

```ts
// A scheduled run held back 140 new grants after a bulk import. Review, then confirm.
const result = await iam.api.packages.reconcile(credential, { tenantId, packageId, confirm: true });
```

## request

Asks for a requestable package for yourself; approvers are notified and one of them decides.

- **Permission:** `iam:packages:request` on the package, from an ordinary session of the tenant.
- **Audited as:** `iam:packages:request`, plus `package:request` with the lapse time, requested end, and
  justification.
- **Errors:** `INVALID_TRANSITION` when the package is not requestable, or it names approvers but none could act
  (an empty approver group and no active manager); `CONFLICT` when you already hold the package or a request of
  yours is still pending; `INVALID_INPUT` from a role session or another tenant's session, or when the end or
  justification the package requires is missing or out of range; `IMPERSONATION_RESTRICTED` from an impersonation
  session.

`expiresAt` is the end you want the access to have, and `justification` the reason, both under the same rules as
`assign`. The request lapses after the tenant's `approvalLifetimeMs`, or at the end you asked for if that comes
first. When the deployment sends email, the approver group's members and, with `managerApproval`, your manager
receive a `package-request` message. Grant `iam:packages:request` through a group everyone belongs to, like
`iam:bindings:activate` for [just-in-time elevation](/docs/guides/privileged-access/elevation).

```ts
const pending = await iam.api.packages.request(memberCredential, {
  tenantId,
  packageId,
  expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000,
  justification: 'On call for the payments team next month',
});
// pending.status === 'pending'; pending.expiresAt is when the request lapses
```

## revoke

Removes a package from a person, taking away exactly the bindings and memberships the assignment still owns.

- **Permission:** `iam:packages:assign` on the package.
- **Audited as:** `iam:packages:assign`, plus `package:revoke` with the removed counts.
- **Errors:** `NOT_FOUND` when the package is not assigned to the person; `INVALID_TRANSITION` for an automatic
  assignment while the package still has its rule; `INVARIANT_VIOLATION` when the removal would break an enforced
  invariant.

The assignment owns its records whichever authority issued them, so revoking needs no grant authority. Records
taken over by hand stay, and a shared membership passes to another of the person's packages that includes the
group. To stop a rule from giving someone the package, exclude them in the rule (for example
`exclude: [{ StringEquals: { 'principal.id': identityId } }]`) or change their attributes.

## update

Changes a package's name, description, contents, request settings, or rule.

- **Permission:** `iam:packages:update` on the package. Setting, changing, or clearing a rule, or changing a rule
  package's roles or groups, also needs `iam:packages:assign` and, except when clearing, the rule-owner checks of
  `create`.
- **Audited as:** `iam:packages:update`, plus `package:auto-rule` (`set`, `change`, `owner`, `contents`, or `clear`)
  when the rule changes.
- **Errors:** `CONFLICT` for a name another package uses; `INVALID_INPUT` when the rule no longer fits new contents,
  `keepAutomaticAssignments` is used without clearing a rule or with more than 5000 automatic holders, or
  `maxDurationMs` is set on a rule package; plus the validation and owner-check errors of `create`.

Manual assignments keep what they were given; contents changes apply to future assignments only. Automatic
assignments follow the package: the reconcile that runs after the save (up to 200 changes, the rest at the next
run) adds and removes their records. Changing a rule package's roles or groups makes you the rule's owner, so a
role added later is always granted under the authority of the person who added it. `autoAssign: null` clears the
rule, and reconciliation then removes the automatic holders unless you pass `keepAutomaticAssignments: true`, which
turns them into manual assignments. Pass `null` to clear `description`, `maxDurationMs`, or `approverGroupId`.

Tightening a package cancels the pending requests it no longer allows, with the reason as the note: turning
`requestable` off, requiring a justification a request lacks, or capping the duration below what a request asked for.
