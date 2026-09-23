# groups

Groups let you grant access to many people at once. Instead of binding the same roles to every member of the
finance team, you bind them once to a "Finance" group and manage who is in it; everyone in the group receives every
role bound to it, and leaving the group removes that access immediately. Memberships can be temporary, which suits
contractors, on-call rotations, and project teams.

## How group access works

A group has no permissions of its own. Access comes from [role bindings](/docs/guides/authorization/roles) whose
subject is the group, so changing membership is, in effect, granting or revoking those roles. That is why adding or
removing a member requires authority over each of the group's bindings, not just permission to edit the group:
someone who could not grant a role directly cannot grant it by putting a person in a group.

Temporary memberships carry an `expiresAt` (epoch milliseconds). They stop counting the moment they lapse, are left
out of `listMembers`, and are removed later by the purge job. Memberships created by an
[access package](/docs/guides/privileged-access/access-packages) are tagged with the package's assignment; editing
one by hand takes it over, so revoking the package no longer removes it.

## addMember

Adds a person to a group so they receive every role bound to the group, optionally until a given time.

- **Permission:** `iam:groups:update` on the group, plus grant authority for each of the group's role bindings.
- **Audited as:** `iam:groups:update`.
- **Errors:** `CONFLICT` when the person is already a live member; `NOT_FOUND` when the group or person is not in
  this tenant; `ACCESS_DENIED` without authority over one of the group's bindings; `SOD_CONFLICT` when the
  membership would give the person a combination of roles a
  [separation-of-duties rule](/docs/guides/authorization/separation-of-duties) forbids.

Pass `expiresAt` to make the membership temporary. Adding someone whose earlier membership has lapsed renews it
instead of failing, and the renewed membership no longer belongs to the access package that originally created it.

```ts
// Give a contractor the team's access for 30 days.
await iam.api.groups.addMember(credential, {
  tenantId,
  groupId,
  identityId,
  expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000,
});
```

## addMembers

Adds up to 100 people to a group in one transaction, all with the same optional expiry.

- **Permission:** `iam:groups:update` on the group, plus grant authority for each of the group's role bindings.
- **Audited as:** `iam:groups:update`.
- **Errors:** `INVALID_INPUT` when `identityIds` is empty; any error `addMember` can raise for one person
  (including `SOD_CONFLICT`) rejects the whole batch.

Use it for cohort onboarding, such as a new class of employees or everyone joining a project on the same day.
Duplicate ids are ignored. Because it is atomic, either everyone is added or no one is.

## create

Creates a group in the tenant.

- **Permission:** `iam:groups:create` on the tenant.
- **Audited as:** `iam:groups:create`.
- **Errors:** `LIMIT_EXCEEDED` when the tenant's plan limit for groups is reached; `INVALID_INPUT` for an empty name
  or a description over 512 characters.

A new group is empty and grants nothing until you bind roles to it with
[`bindings.create`](/docs/reference/api/bindings#create) and add members.

## delete

Deletes a group together with its memberships, its role bindings, their activations, and its relationship tuples.

- **Permission:** `iam:groups:delete` on the group, plus grant authority for each of its role bindings.
- **Audited as:** `iam:groups:delete`.
- **Errors:** `RESOURCE_IN_USE` (409) when an access package still grants the group or names it in an automatic
  assignment rule, or when the group approves package requests or eligible-binding activations.

The in-use checks exist so deleting a group never silently changes who can approve requests or what a package
grants: point those at another group first.

## get

Returns one group by id.

- **Permission:** `iam:groups:read` on the group.
- **Audited as:** `iam:groups:read`.
- **Errors:** `NOT_FOUND` when the group is not in this tenant.

## list

Lists every group in the tenant.

- **Permission:** `iam:groups:read` on the tenant.
- **Audited as:** `iam:groups:read`.

## listMembers

Lists the current members of a group, with `membershipExpiresAt` on temporary memberships.

- **Permission:** `iam:groups:read` on the group.
- **Audited as:** `iam:groups:read`.
- **Errors:** `NOT_FOUND` when the group is not in this tenant.

Lapsed memberships are left out even before the purge job removes them, so the list always matches who currently
receives the group's roles. Members are returned as public identities, without credential material.

## removeMember

Removes a person from a group, ending the access the group's roles gave them.

- **Permission:** `iam:groups:update` on the group, plus grant authority for each of the group's role bindings.
- **Audited as:** `iam:groups:update`.

Any [just-in-time activations](/docs/guides/privileged-access/elevation) the person had of the group's eligible
bindings end at the same time, so removing someone from a group cannot leave them elevated. Removing a person who is
not a member succeeds and changes nothing.

## update

Renames a group or changes its description.

- **Permission:** `iam:groups:update` on the group.
- **Audited as:** `iam:groups:update`.
- **Errors:** `INVALID_INPUT` when neither `name` nor `description` is given.

## updateMember

Extends, shortens, or clears the expiry of an existing membership.

- **Permission:** `iam:groups:update` on the group, plus grant authority for each of the group's role bindings.
- **Audited as:** `iam:groups:update`.
- **Errors:** `NOT_FOUND` when the person is not a live member of the group.

Pass `expiresAt: null` to make a temporary membership permanent. Editing a membership that an access package
created takes it over: revoking the package will no longer remove it.
