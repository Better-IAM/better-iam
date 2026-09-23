# roleMining

Role mining reads who holds which roles today and suggests simpler, narrower ways to grant the same access. Over
time, direct grants pile up, roles get copied, and people keep access after they change teams. This group finds
those patterns, compares people with their peers, and uses recorded access usage to show which grants nobody uses,
so you can clean up with evidence instead of guesswork. It is the "simplify" and "measure" part of
[access governance](/docs/guides/governance/usage-and-mining).

## How role mining reads a tenant

Suggestions, outliers, and right-sizing work on a snapshot of the tenant taken inside one transaction: active
identities that have not expired, live role bindings (started and not expired), and live group memberships. A role reaches a person through
their own binding or through a group they belong to. The protected Owner role is always left out, so mining never
suggests touching ownership.

Suggestions and findings are advisory: every read method only reads, and nothing changes until you call
[`apply`](#apply) or edit roles, bindings, and packages yourself. Suggestion IDs are deterministic (the same
condition always yields the same ID), so a suggestion listed earlier can be applied later as long as it still
holds.

All read methods need `iam:analysis:read` on `iam/analysis/*`. The console's Organization section uses the same
calls, and the `mine-roles` [CLI command](/docs/reference/cli#mine-roles) prints suggestions and outliers for a
weekly report.

## Access usage tracking

`usage`, `rightSize`, and `reviewRecommendations` rely on recorded usage, which is off until you turn it on with
the `accessUsage` option (`accessUsage: true`, or `{ flushIntervalMs, maxBuffered }`). When it is on, every allowed
authorization check and every allowed provisioning operation is counted in memory per person and action and
written in batches (every minute by default), so the request path never waits on storage. Root overrides and
actions taken during an impersonation ("view as") session are not counted as the person's own use.

Usage only proves what happened since tracking started. Each result says when tracking began for the tenant, and
the right-sizing and review methods tell you whether the recorded period covers the whole window you asked about.
Call `iam.flushAccessUsage()` on shutdown so buffered counts are not lost.

## apply

Carries out a `group-binding` or `redundant-binding` suggestion: binds the role to the group once and removes the
direct bindings it replaces.

- **Permission:** `iam:analysis:update` on `iam/analysis/{suggestionId}`, plus `iam:bindings:create` on the role
  (for a group binding) and `iam:bindings:delete` on each removed binding. The bindings move under the grant
  authority they already use, so you must hold that authority or be a root administrator.
- **Audited as:** `iam:analysis:update`.
- **Errors:** `NOT_FOUND` when the suggestion no longer holds (list suggestions again); `INVALID_INPUT` for a
  `bundle` or `duplicate-roles` suggestion, or a group binding whose direct bindings come from different grant
  authorities (`applicable: false`); `ACCESS_DENIED` without the binding rights or the authority;
  `INVARIANT_VIOLATION` when an enforced [access invariant](/docs/guides/governance/change-safety) would newly
  break.

The suggestion is recomputed inside the transaction, so it applies only while the condition still holds, and
either every binding change happens or none does. Pass the same `minIdentities` and `minRoles` you used with
`suggest`: the suggestion is looked up again with those settings, and different settings can make it disappear.

Bundles are not applied here. Turn a bundle into an access package with
[`packages.create`](/docs/reference/api/packages#create), and merge duplicate roles by moving bindings to one
role and deleting the others.

```ts
const { suggestions } = await iam.api.roleMining.suggest(credential, { tenantId, kinds: ['redundant-binding'] });
const result = await iam.api.roleMining.apply(credential, { tenantId, suggestionId: suggestions[0].id });
// result.removedBindingIds: the direct bindings that were deleted
```

## outliers

Finds people whose roles differ from their peers': roles few peers hold and roles most peers hold that the person
lacks.

- **Permission:** `iam:analysis:read` on `iam/analysis/*`.
- **Audited as:** `iam:analysis:read`.
- **Errors:** `INVALID_INPUT` when `peerBy` is neither `manager` nor `attribute:NAME` for a declared identity
  attribute, when `threshold` or `commonShare` is not above 0 and at most 1, or when `minPeers` is out of range.

Peers are people who share a manager (`peerBy: 'manager'`, the default) or the same value of a declared identity
attribute (`peerBy: 'attribute:department'`). A role is **unusual** when fewer than `threshold` (default 0.25) of
the person's peers hold it, which often means access that outlived a move. A role is **missing** when at least
`commonShare` (default 0.8) of the peers hold it, which often means a joiner who still lacks something. Peer
groups with fewer than `minPeers` other people (default 3) are skipped. Eligible (just-in-time) bindings count as
held.

```ts
const { outliers } = await iam.api.roleMining.outliers(credential, {
  tenantId,
  peerBy: 'attribute:department',
  threshold: 0.2,
});
```

## reviewRecommendations

Suggests a keep or revoke decision, with a reason, for every item of an
[access-certification](/docs/guides/governance/certifications) campaign.

- **Permission:** `iam:analysis:read` on `iam/analysis/*`.
- **Audited as:** `iam:analysis:read`.
- **Errors:** `NOT_FOUND` when the campaign is not in this tenant; `INVALID_INPUT` when `unusedDays` is outside 1
  to 3650.

Each recommendation is based on evidence. It is `revoke` when the account is disabled, expired, or gone
(`basis: 'status'`). Otherwise, when recorded usage covers the last `unusedDays` (default 90), it is `keep` if the
person used any of the role's actions in that window and `revoke` if not (`basis: 'usage'`). Before usage covers
the window, the person's last sign-in decides (`basis: 'sign-in'`). Items for group bindings, and service accounts without usage
data, get `none`. Reviewers still decide; the console shows the suggestion beside each open item.

## rightSize

Lists every live binding whose holder used none or only some of the role's actions in a window, plus, per role,
the actions nobody used.

- **Permission:** `iam:analysis:read` on `iam/analysis/*`.
- **Audited as:** `iam:analysis:read`.
- **Errors:** `INVALID_INPUT` when `unusedDays` is outside 1 to 3650.

This is least-privilege right-sizing. An entry is `unused` when the holder used none of the role's actions within
`unusedDays` (default 90) and `partial` when they used some. Per role, `neverUsed` lists actions no holder used,
which are candidates for a narrower role. A role's actions are the known actions its allow statements (own,
attached, and inherited) can match; resources and conditions are not considered.

Check `complete` before acting: it is `false` until usage has been recorded for the whole window, and until then
"unused" only means "not used since tracking started". `tracking` is `false` when the `accessUsage` option is off.

## suggest

Lists ways to simplify how the tenant grants access, most actionable first.

- **Permission:** `iam:analysis:read` on `iam/analysis/*`.
- **Audited as:** `iam:analysis:read`.
- **Errors:** `INVALID_INPUT` for an unknown kind in `kinds`, or `minIdentities` (2 to 10 000), `minRoles` (2 to
  50), or `limit` (1 to 500) out of range.

There are four kinds of suggestion:

- **`redundant-binding`**: direct bindings that a permanent group membership already covers, with the same role,
  the same grant authority, and a group binding that lasts at least as long. Removing them changes nothing today.
- **`group-binding`**: a role that every member of a group (all active, all with permanent memberships) holds
  through their own direct binding. Bind it to the group once, so joiners get it and leavers lose it.
- **`duplicate-roles`**: roles whose statements are identical.
- **`bundle`**: role combinations many people hold together. Grant them as one
  [access package](/docs/guides/privileged-access/access-packages) instead of binding each role separately.

`minIdentities` (default 3) is how many people must share a pattern, and `minRoles` (default 2) is the smallest
combination reported as a bundle. `limit` (default 50) caps the list, while `summary` counts every suggestion by
kind. Each suggestion names the roles, people, and group involved, the bindings it would remove, a `savings`
estimate, and whether `apply` can carry it out.

## usage

Returns the recorded access usage of the tenant: per person and action, when it was first and last allowed and
how often.

- **Permission:** `iam:analysis:read` on `iam/analysis/*`.
- **Audited as:** `iam:analysis:read`.
- **Errors:** `INVALID_INPUT` when `limit` (1 to 1000) or `offset` is out of range.

Records are sorted by last use, newest first; pass `identityId` to see one person's history. Buffered usage is
written before the read, so the result is current. `tracking` tells you whether the deployment records usage at
all, and `trackingSince` when this tenant's first use was recorded. Counts are approximate when several server
instances record at once.
