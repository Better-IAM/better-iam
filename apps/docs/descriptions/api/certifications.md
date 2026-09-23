# certifications

Certification campaigns turn periodic access reviews into recorded decisions. A campaign snapshots the role bindings
under review, reviewers keep or revoke each one, and closing the campaign removes the revoked bindings and records
what happened to every item, which is the evidence auditors ask for. See the
[certifications guide](/docs/guides/governance/certifications) for the full workflow.

Campaign permissions are checked on the internal resource `iam/certifications/*` for tenant-wide calls (`create`,
`list`) and on `iam/certifications/{campaignId}` for one campaign, so you can scope who manages or reviews which
campaign.

## Reviewers and who may decide

Every item is one binding as it stood when the campaign opened. Who decides it depends on the campaign's
`reviewerMode`:

- **`named`** (the default): the people in `reviewerIds` decide every item with `decide`. When `reviewerIds` is
  empty, anyone holding `iam:certifications:review` on the campaign may decide.
- **`manager`**: each person's items are assigned to their manager (`Identity.managerId`) when that manager is an
  active, unexpired member of the tenant. Managers decide their items with `review`, which needs no certification
  permission, and find them with `listMine`. Items without an active manager, and items held by groups, fall back to
  the named reviewers (or to anyone holding `iam:certifications:review` when none are named). Through `decide`, a
  manager-assigned item may be decided only by that manager or by a holder of `iam:certifications:manage`.

Nobody decides on their own access, directly or through a group they belong to (`SELF_REVIEW`). A decision can be
changed until the campaign closes. [`roleMining.reviewRecommendations`](/docs/reference/api/role-mining#reviewrecommendations)
suggests keep or revoke for every item from recorded usage and sign-in activity.

## What closing does

Closing applies the campaign in one transaction. Items decided `revoke`, and undecided items when the campaign's
`undecided` is `revoke`, have their binding deleted under the closer's
[grant authority](/docs/guides/authorization/roles#grant-authorities); everything else is kept. Each item records an
`outcome`:

- `kept`: the binding stays.
- `revoked`: the binding was removed (with its just-in-time activations), audited as `iam:bindings:delete`.
- `already-removed`: the binding to revoke was already gone, or no longer matched the item's role and subject.
- `revocation-failed`: the closer may not remove it. A binding can be removed only by the administrator whose
  authority issued it or by a root administrator, so a binding someone else granted is left for them, with the
  reason in `outcomeDetail`.

A binding an [access package](/docs/guides/privileged-access/access-packages) created is removed like any other: a
manual assignment then reports `broken`, and an automatic assignment gets the binding back at the next reconcile
while the person still matches the rule. To remove birthright access for good, change the rule.

Campaigns created with `autoClose: true` and a `dueAt` are closed by the deployment job
[`iam.closeOverdueCertifications()`](/docs/reference/api#closeoverduecertifications) (CLI `close-certifications`)
once due, under the creator's authority, audited as `certification:auto-close` by `deployment-operator`.

## close

Closes an open campaign and applies it, removing the bindings reviewers revoked.

- **Permission:** `iam:certifications:manage` on the campaign, with
  [recent authentication](/docs/guides/authentication/sessions#recent-authentication).
- **Audited as:** `iam:certifications:manage`, plus one `iam:bindings:delete` per removed binding.
- **Errors:** `RECENT_AUTH_REQUIRED` when your sign-in is not recent or the credential is temporary;
  `IMPERSONATION_RESTRICTED` from an impersonation session; `CONFLICT` when the campaign is already closed;
  `NOT_FOUND` when it is not in this tenant; `INVARIANT_VIOLATION` when the removals would break an enforced
  [invariant](/docs/guides/governance/change-safety).

The result is the closed campaign with `outcomes`, the number of items per outcome. Close as the administrator who
granted the bindings, or as root, to avoid `revocation-failed` items. The closed campaign keeps every decision and
outcome until you delete it.

```ts
const closed = await iam.api.certifications.close(credential, { tenantId, campaignId });
// closed.outcomes: { kept: 41, revoked: 6, 'already-removed': 1, 'revocation-failed': 0 }
```

## create

Opens a campaign over the tenant's current role bindings and notifies the reviewers.

- **Permission:** `iam:certifications:manage` on `iam/certifications/*`.
- **Audited as:** `iam:certifications:manage`.
- **Errors:** `LIMIT_EXCEEDED` (409) when more than 5000 bindings would be reviewed; `INVALID_INPUT` for an empty
  name, a listed role that is unknown or protected, a `dueAt` that is not in the future, `autoClose` without `dueAt`,
  or an invalid `subjectType`, `reviewerMode`, or `undecided`; `NOT_FOUND` when a reviewer is not in this tenant or
  is deleted.

The campaign covers the live bindings of every non-protected role, or only of `roleIds`, optionally only those held
by people or by groups (`subjectType`). Bindings that have not started yet are left out; eligible bindings are
included and flagged. `undecided` (default `keep`) says what closing does with items nobody decided: `revoke` makes
silence mean removal. When the deployment sends email, each reviewer receives one `certification-review` message
with their own item count. The result carries the campaign, its `progress`, and `items`, the number of bindings it
covers.

```ts
const campaign = await iam.api.certifications.create(credential, {
  tenantId,
  name: 'Q4 admin review',
  roleIds: [adminRole.id, billingAdminRole.id],
  reviewerMode: 'manager',
  reviewerIds: [securityLead.id], // items without an active manager go here
  dueAt: Date.parse('2026-12-15T17:00:00Z'),
  autoClose: true,
  undecided: 'revoke',
});
```

## decide

Records keep or revoke decisions on up to 200 items of an open campaign.

- **Permission:** `iam:certifications:review` on the campaign; when the campaign names reviewers, you must be one of
  them, except for items assigned to you as a manager.
- **Audited as:** `iam:certifications:review`.
- **Errors:** `SELF_REVIEW` for an item that certifies your own access; `ACCESS_DENIED` when you are not a reviewer
  of the campaign or the item is assigned to someone else's manager and you lack `iam:certifications:manage`;
  `CONFLICT` when the campaign is closed; `INVALID_INPUT` for an empty batch, more than 200 entries, or a decision
  other than `keep` or `revoke`; `NOT_FOUND` for an item that is not in this campaign.

The batch is atomic: one refused entry rejects them all. Deciding an item again replaces the earlier decision and
its note. A `note` holds at most 500 characters.

```ts
await iam.api.certifications.decide(reviewerCredential, {
  tenantId,
  campaignId,
  decisions: [
    { itemId: 'item_1', decision: 'keep' },
    { itemId: 'item_2', decision: 'revoke', note: 'Moved to finance in July' },
  ],
});
```

## delete

Deletes a closed campaign and all its items.

- **Permission:** `iam:certifications:manage` on the campaign.
- **Audited as:** `iam:certifications:manage`.
- **Errors:** `CONFLICT` when the campaign is still open (close it first); `NOT_FOUND` when it is not in this tenant.

Closed campaigns are evidence; delete one only when your retention period for review records has passed.

## get

Returns one campaign with its items and progress.

- **Permission:** `iam:certifications:read` on the campaign.
- **Audited as:** `iam:certifications:read`.
- **Errors:** `NOT_FOUND` when the campaign is not in this tenant.

Items are sorted by role and subject, each with its decision, reviewer, and, once closed, its outcome. `progress`
counts `total`, `decided`, `keep`, and `revoke`. `mine: true` leaves out the items that certify your own access
(directly or through a group), which you could not decide anyway.

## list

Lists the tenant's campaigns, newest first, each with its progress.

- **Permission:** `iam:certifications:read` on `iam/certifications/*`.
- **Audited as:** `iam:certifications:read`.

Pass `status: 'open'` or `'closed'` to filter.

## listMine

Lists the open campaigns that have items assigned to you as a manager, with only those items.

- **Permission:** None beyond an ordinary session of the tenant (not an assumed role or another tenant's session).
- **Audited as:** Not audited; it only reads.
- **Errors:** `ACCESS_DENIED` from a role session or a session of another tenant.

This is the data a manager's review screen needs. It returns only manager-mode assignments; named reviewers use
`get` with `mine: true` instead.

## remind

Emails every reviewer who still has undecided items a reminder with their pending count.

- **Permission:** `iam:certifications:manage` on the campaign.
- **Audited as:** `iam:certifications:manage`, plus `certification:remind` with the counts.
- **Errors:** `DELIVERY_REQUIRED` when the deployment has no email delivery callback; `CONFLICT` when the campaign
  is closed; `NOT_FOUND` when it is not in this tenant.

Managers are reminded of their assigned items and named reviewers of the undecided items that fall back to them.
Only active reviewers with an email address are counted. When the campaign names no reviewers, nobody is reminded of
unassigned items. Returns `reminded` (people emailed) and `pending` (undecided items). Send one a few days before
`dueAt`.

## review

Records a manager's keep or revoke decisions on up to 200 items assigned to them, without a certification permission.

- **Permission:** None beyond an ordinary, non-impersonated session of the tenant; every item must be assigned to
  you.
- **Audited as:** `certification:review`, with the number of keep and revoke decisions.
- **Errors:** `ACCESS_DENIED` for an item that is not assigned to you, or from a role session or another tenant's
  session; `IMPERSONATION_RESTRICTED` from an impersonation session; `SELF_REVIEW` for your own access; `CONFLICT`
  when the campaign is closed; `INVALID_INPUT` for an empty batch, more than 200 entries, or an invalid decision.

This lets line managers take part in reviews without holding an administrator role: being assigned the item is the
authorization. Like `decide`, the batch is atomic and a later decision replaces an earlier one.

```ts
await iam.api.certifications.review(managerCredential, {
  tenantId,
  campaignId,
  decisions: [{ itemId, decision: 'revoke', note: 'No longer on the payments team' }],
});
```
