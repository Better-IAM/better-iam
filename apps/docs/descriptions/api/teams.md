# teams

Teams are the working units inside an organization: Platform, Site Reliability, the Payments squad. A team can sit
under another team, has maintainers who manage its membership themselves, can take join requests, and gives its
members access through roles bound to its backing group. Departments, the reporting structure, are the
[`departments`](/docs/reference/api/departments) group.

## How teams grant access

Every team owns a backing group (`groupId`, named `team:{slug}`). Bind roles to it with
[`bindings.create`](/docs/reference/api/bindings#create) (`subjectType: 'group'`). The backing group holds the live
members of the team and of every team below it, so a child team's members receive the parent team's access. Because
it is an ordinary group, separation of duties, invariants, access reviews, role mining, relationships, and
`principal.groups` all see team members.

Only this API writes a backing group's members: the groups API refuses them with `TEAM_MANAGED` (409), and access
packages, invitations, onboarding flows, and configuration sync leave them alone. Policies see `principal.teams`: the
IDs of the teams a person belongs to directly and of every team above them.

## Team sync

A team with `syncGroupIds` (up to ten ordinary groups, such as SCIM-provisioned directory groups) keeps their live
members (active people) as members, marked `source: 'sync'` and ending when their last source membership does. The
team follows `groups.addMember`, `groups.updateMember`, `groups.removeMember`, and every SCIM push of a source group
(audited with actor `directory-sync`); people added by hand are never touched. Synced members are changed through the
source group: `removeMember` and a new end in `updateMember` refuse them with `INVALID_TRANSITION`. Deleting a source
group fails with `RESOURCE_IN_USE` while a team syncs from it. `syncGroupIds: null` stops syncing and removes the
synced members.

## Maintainers

A maintainer of a team, or of any team above it, may add, update and remove members, list candidates, and decide join
requests from their own user session without `iam:teams:update`, unless the team's `memberManagement` is `admins`.
Such calls are audited with `via: team-maintainer`; separation-of-duties rules and enforced invariants still apply.
Administrators need `iam:teams:update` and, like [`groups.addMember`](/docs/reference/api/groups#addmember),
authority over the bindings of the team's backing group and of the teams above it. Members of a team (directly or
through a team below it) may read it with `get` and `listMembers`.

## Birthright packages

[Access package rules](/docs/guides/privileged-access/automatic-assignment) may test `identity.teams`: the team IDs a
person belongs to and those above them (a membership team sync copied from a group counts only through a group
membership no package created). The membership calls here re-evaluate the rules for the people they touch once they
commit, so someone added to a team gets its birthright packages at once and loses them when they leave.

## Membership reviews

A review asks a team's maintainers to confirm who still belongs. An administrator opens it with `startReview`; every
live manual member becomes an item (members team sync manages are reviewed through their source groups). Maintainers of
the team or a team above, and administrators, record `keep` or `remove` with `decideReview`; nobody decides on their
own membership. Nothing changes until the review completes (`completeReview`, or the scheduler job
`iam.closeOverdueTeamReviews()` once `dueAt` passes): then people decided `remove` leave the team and people nobody
decided on follow `onUndecided`. Removals are audited as `team:member:remove` with `source: review`, and birthright
packages follow at once.

## addMember

Adds a person to a team as a `member` (default) or `maintainer`, optionally until `expiresAt`.

- **Permission:** `iam:teams:update` on `iam/{teamId}`, or maintaining the team or a team above it.
- **Audited as:** `iam:teams:update` and `team:member:add` (`identityId`, `role`, `source`, `expiresAt`, `via`).
- **Errors:** `CONFLICT` (409) when the person is already a live member; `INVALID_INPUT` for a service account, agent,
  or inactive person; `GRANT_AUTHORITY_REQUIRED` / `ACCESS_DENIED` when an administrator lacks authority over what the
  team holds; `SOD_CONFLICT` (409) when the roles the team brings conflict with the person's; `NOT_FOUND`.

A pending join request of the person is marked approved.

```ts
await iam.api.teams.addMember(credential, {
  tenantId,
  teamId,
  identityId,
  role: 'member',
  expiresAt: Date.now() + 30 * 86_400_000,
});
```

## addMembers

Adds up to 100 people with the same role and expiry in one transaction; one failure rejects the batch.

- **Permission:** as `addMember`.
- **Audited as:** `iam:teams:update` and one `team:member:add` per person.
- **Errors:** as `addMember`; `INVALID_INPUT` for an empty or oversized list.

## approveRequest

Grants a pending join request: the requester joins as a member (optionally until `expiresAt`) and is emailed
(`team-join-decided`). Nobody decides their own request.

- **Permission:** `iam:teams:update` on the team, or maintaining it or a team above it.
- **Audited as:** `iam:teams:update`, `team:member:add` (`source: approve`), and `team:join:approve`.
- **Errors:** `INVALID_TRANSITION` (409) when the request is no longer pending (decided, withdrawn, or lapsed);
  `ACCESS_DENIED` for your own request; `NOT_FOUND`.

## cancelRequest

Withdraws your own pending join request.

- **Permission:** None beyond an ordinary user session of the organization (not while impersonating).
- **Audited as:** `team:join:cancel`.
- **Errors:** `INVALID_TRANSITION` when the request is no longer pending; `NOT_FOUND` for someone else's request.

## cancelReview

Cancels an open membership review without changing the team.

- **Permission:** `iam:teams:update` on the team (administrators; maintainers cannot cancel).
- **Audited as:** `iam:teams:update` and `team:review:cancel`.
- **Errors:** `INVALID_TRANSITION` (409) when the review is no longer open; `NOT_FOUND`.

## candidates

People who could be added: active people of the organization who are not direct members, matched on name or email by
`query`, at most `limit` (default 50, up to 200). Maintainers use it to pick people without `iam:identities:read`.

- **Permission:** `iam:teams:update` on the team, or maintaining it or a team above it.
- **Audited as:** `iam:teams:update`.

## completeReview

Completes an open review: people decided `remove` leave the team, and people nobody decided on follow the review's
`onUndecided`. Returns the review with its `outcome` (`kept`, `removed`, `undecided`, and `gone` for people who had
already left or are now managed by team sync).

- **Permission:** `iam:teams:update` on the team, or maintaining it (or a team above) once every person is decided.
- **Audited as:** `iam:teams:update` (maintainers with `via: team-maintainer`), `team:member:remove` (`source: review`)
  per removal, and `team:review:complete` with the counts.
- **Errors:** `INVALID_TRANSITION` (409) when the review is no longer open, or when a maintainer completes it with
  people still undecided; `NOT_FOUND`.

## create

Creates a team with its backing group. `slug` defaults to one derived from the name; `parentId` nests it;
`departmentId` files it under a department; `joinPolicy` (`closed` or `request`) and `memberManagement`
(`maintainers` or `admins`) set how people join; `maintainerIds` names up to 20 maintainers; `syncGroupIds` turns on
[team sync](#team-sync).

- **Permission:** `iam:teams:create` on the tenant. With `parentId`, also `iam:teams:update` on the parent and
  authority over what the parent (and the teams above it) hold.
- **Audited as:** `iam:teams:create`, `team:create`, and `team:member:add` per maintainer.
- **Errors:** `CONFLICT` (409) when the slug is taken; `INVALID_INPUT` for a bad slug, more than ten levels of nesting,
  or more than 20 maintainers; `LIMIT_EXCEEDED` past 1000 teams or the tenant's group limit.

```ts
const platform = await iam.api.teams.create(credential, {
  tenantId,
  name: 'Platform',
  joinPolicy: 'request',
  maintainerIds: [leadId],
});
await iam.api.bindings.create(credential, {
  tenantId,
  roleId,
  subjectType: 'group',
  subjectId: platform.groupId,
});
```

## decideReview

Records `keep` or `remove` for up to 200 people under an open review, each with an optional `note`. A later decision
replaces an earlier one; nothing changes in the team until the review completes.

- **Permission:** `iam:teams:update` on the team, or maintaining it (or a team above).
- **Audited as:** `iam:teams:update` (maintainers with `via: team-maintainer`) and `team:review:decide` with the counts.
- **Errors:** `ACCESS_DENIED` for a decision on your own membership; `NOT_FOUND` for a person who is not under review;
  `INVALID_TRANSITION` (409) when the review is no longer open; `INVALID_INPUT` without 1-200 decisions.

```ts
await iam.api.teams.decideReview(maintainerSession, {
  tenantId,
  reviewId,
  decisions: [
    { identityId: aliceId, decision: 'keep' },
    { identityId: carolId, decision: 'remove', note: 'Moved to Sales' },
  ],
});
```

## delete

Deletes a team, its memberships and join requests, and its backing group with the bindings and relationships on it.

- **Permission:** `iam:teams:delete` on the team, and authority over the backing group's bindings.
- **Audited as:** `iam:teams:delete` and `team:delete`.
- **Errors:** `RESOURCE_IN_USE` (409) while teams sit below it, while the backing group approves requests for an
  eligible binding or a package, or while an access package rule names the team (`identity.teams`) or its backing
  group (`identity.groups`).

## denyRequest

Refuses a pending join request; the requester is emailed with the `note`.

- **Permission:** as `approveRequest`.
- **Audited as:** `iam:teams:update` and `team:join:deny`.
- **Errors:** as `approveRequest`.

## get

One team with its path (the teams above it), its children, department, maintainers, total member count (with the teams
below), and the roles its members hold through it or a team above (`inherited`).

- **Permission:** `iam:teams:read` on the team, or belonging to it (directly or through a team below it).

## getReview

One membership review with every person under it: their role, the decision, who made it and when, and the note.

- **Permission:** `iam:teams:read` on the team, or maintaining it (or a team above).
- **Errors:** `NOT_FOUND` for a review of another team or tenant.

## leave

Leaves a team you belong to directly.

- **Permission:** None beyond an ordinary user session of the organization (not while impersonating).
- **Audited as:** `team:leave`.
- **Errors:** `NOT_FOUND` when you are not a direct member.

## list

Every team with member, maintainer, and child counts, in name order. Filters: `parentId` (null for top-level teams),
`departmentId`, and `query` (name or slug).

- **Permission:** `iam:teams:read` on the tenant.

## listForIdentity

The teams one person belongs to directly, with their role, expiry, and the teams above each one.

- **Permission:** `iam:teams:read` on `iam/{identityId}`.

## listMembers

The team's live direct members with their role, expiry, and who added them; `includeChildTeams` adds the members of
every team below, each with the team they belong to.

- **Permission:** `iam:teams:read` on the team, or belonging to it.

## listMine

Your teams (with role, expiry, and parents), your join requests (newest first), the teams that take join requests that
you are not in, and the open membership reviews of teams you maintain (eviews, soonest due first, with how many
people other than you are still undecided).

- **Permission:** None beyond an ordinary user session of the organization.

## listRequests

A team's join requests, pending by default (`status` picks another state; lapsed requests read as `expired`).

- **Permission:** `iam:teams:read` on the team, or maintaining it or a team above it.

## listReviews

Membership reviews, newest first (at most 100), without their items: of one team with `teamId`, or of every team.
`status` (`open`, `completed`, `cancelled`) filters.

- **Permission:** With `teamId`, `iam:teams:read` on the team or maintaining it (or a team above); without it,
  `iam:teams:read` on the tenant.

## reconcile

Runs [team sync](#team-sync) for every synced team (`synced`: team memberships added, removed, and updated), then
recomputes every backing group from team membership, after a restore, an import, or a manual repair: how many group
memberships were added, removed, and updated.

- **Permission:** `iam:teams:update` on the tenant.

## removeMember

Removes a direct member; the backing groups and the person's activations of their eligible bindings follow.

- **Permission:** as `addMember`.
- **Audited as:** `iam:teams:update` and `team:member:remove`.
- **Errors:** `NOT_FOUND` when the person is not a live direct member; `INVALID_TRANSITION` (409) for a member
  [team sync](#team-sync) manages.

## requestToJoin

Asks to join a team whose `joinPolicy` is `request`, with an optional `justification`. The team's maintainers (or,
without any, those of the nearest team above) are emailed `team-join-request`; the request lapses after fourteen days.

- **Permission:** None beyond an ordinary user session of the organization (not while impersonating).
- **Audited as:** `team:join:request`.
- **Errors:** `INVALID_TRANSITION` (409) when the team does not take requests; `CONFLICT` when you are already a member
  or already asked.

## startReview

Opens a membership review of the team, due at `dueAt` (one to 90 days ahead; in 14 days by default), with an optional
`note` for the maintainers. `onUndecided` (`keep` by default, or `remove`) settles the people nobody decides on. The
team's maintainers (or, without any, those of the nearest team above) are emailed `team-review-requested`.

- **Permission:** `iam:teams:update` on the team (administrators).
- **Audited as:** `iam:teams:update` and `team:review:start`.
- **Errors:** `CONFLICT` (409) while another review of the team is open; `INVALID_TRANSITION` (409) when the team has
  no manual members; `INVALID_INPUT` for a `dueAt` outside one to 90 days.

```ts
const review = await iam.api.teams.startReview(credential, {
  tenantId,
  teamId,
  onUndecided: 'remove',
  note: 'Quarterly access review',
});
```

## suggestBirthright

Roles and groups that most of a team's members already hold by hand, proposed as a ready-made automatic access
package whose rule names the team.

- **Permission:** `iam:analysis:read` on the tenant.
- **Audited as:** Not audited; it only reads.
- **Errors:** `INVALID_INPUT` for `minShare` outside 0.5-1; `NOT_FOUND` for an unknown `teamId`.

A team's people are its members and those of every team below it (who a rule naming it would match). It works like
[`departments.suggestBirthright`](/docs/reference/api/departments#suggestbirthright): plain grants held by at least
`minShare` (default 0.8) of at least `minPeople` (default 3) people, never repeating what is suggested for a team above
or what automatic packages already grant, each with a `package` ready for `packages.create`. A child team whose
members all belong to its parent's suggestion gets none of its own.

## update

Renames, re-slugs, re-describes, moves (`parentId`, null for top level), or re-files (`departmentId`, null to clear) a
team, or changes `joinPolicy`, `memberManagement`, or `syncGroupIds` ([team sync](#team-sync); null stops it). Moving recomputes the backing groups of the old and the new
parents.

- **Permission:** `iam:teams:update` on the team; moving under a parent also needs `iam:teams:update` on it and
  authority over what it holds. Maintainers cannot change settings.
- **Audited as:** `iam:teams:update` and `team:update` (`fields`, and the parents when moved).
- **Errors:** `INVALID_INPUT` when moving under itself or a team below it, or past ten levels; `CONFLICT` for a taken
  slug.

## updateMember

Changes a member's `role` or expiry (`expiresAt: null` makes the membership permanent).

- **Permission:** as `addMember`.
- **Audited as:** `iam:teams:update` and `team:member:update`.
- **Errors:** `NOT_FOUND` when the person is not a live direct member; `INVALID_TRANSITION` (409) for a new end of a
  synced membership (it follows the source group).
