# applications

The application catalog behind the "My apps" launcher: the tools an organization gives its people, and who has each.
An app is an OpenID Connect client of this deployment (`oauthClientId`, kind `oidc`) or a plain link to any other tool
(kind `link`). Administrators give each app to everyone or assign it to people and groups, optionally until a date;
people open their apps from the launcher, every launch is recorded and audited, and people without an app can request
it through an access package. For an `oidc` app the built-in OAuth provider enforces the assignments: through the
`clientAllowed` hook `iam.protocolHost` supplies, it refuses to issue or refresh tokens for people without the app. See
the [application catalog guide](/docs/guides/governance/applications); the repository guide is
`docs/applications.md`.

## Who has an app

A person has an app when it is enabled and its `visibility` is `everyone`, or it is assigned to them, or it is assigned
to a group they belong to, counting only assignments and memberships that have not ended. Only active, unexpired
people have apps: service accounts, agents, and disabled, expired or deleted accounts have none. `via` says why: `direct`, else `group`,
else `everyone`. Assignments are kept whatever the visibility, so switching an app to `assigned` leaves exactly the
assigned people and groups with it.

## Permissions

`iam:applications:read` covers `list`, `listAssignments`, `usage` and `check`; `iam:applications:manage` covers
`create`, `update` and `delete`; `iam:applications:assign` covers `assign`, `unassign` and `removeUnused`. Actions are
checked on `iam/TENANT_ID` for `create`, `list`, `usage`, `check` and `listAssignments` without `appId`, and on the
app for `update`, `delete`, `assign`, `listAssignments` with `appId`, `removeUnused` and `unassign` (the assignment's
app). People's email addresses and names appear in `listAssignments` and `usage` only for callers also allowed
`iam:identities:read` on the tenant. `mine` and `launch` need no permission, only a person's own signed-in session of
the tenant. The deployment's own code checks access with `iam.applications.allowed`, which takes no credential and is
not audited (see [`check`](#check)). `iam.sweepExpired()` deletes assignments past their end, and deleting a person or
a group removes their assignments.

## assign

Gives an app to a person or a group, optionally until `expiresAt`.

- **Permission:** `iam:applications:assign` on the app.
- **Audited as:** `iam:applications:assign`, plus `app:assign` with the app key, `subjectType`, `subjectId` and
  `expiresAt`.
- **Errors:** `INVALID_INPUT` for a `subjectType` other than `identity` or `group`, an identity that is not a person
  (service accounts and agents), or an `expiresAt` not in the future or more than ten years away; `NOT_FOUND` when the
  app, person or group is not in this tenant, or the person is deleted; `LIMIT_EXCEEDED` (409) for a new assignment
  to an app that already has 10,000 (assign groups instead).

Assigning the same person or group again replaces the assignment: the new `expiresAt` (none when left out) applies,
and `assignedBy` and `assignedAt` become the caller and now. An assignment stops counting the moment it ends. The
result is the assignment.

```ts
await iam.api.applications.assign(credential, {
  tenantId,
  appId,
  subjectType: 'group',
  subjectId: salesGroupId,
});
```

## check

Tells whether a person may use an app, by `appId` or by the app's `oauthClientId`, for sign-in pages that enforce assignments.

- **Permission:** `iam:applications:read` on the tenant.
- **Audited as:** `iam:applications:read`.
- **Errors:** `INVALID_INPUT` when the call names both or neither of `appId` and `oauthClientId`; `NOT_FOUND` for an
  unknown `appId`.

The result is `{ allowed, governed, appId? }`. An `oauthClientId` that no app names is not governed by the catalog:
`{ allowed: true, governed: false }`. For an app, `governed` is `true` and `allowed` says whether the person has it
now under [who has an app](#who-has-an-app); an identity that does not exist or belongs to another tenant, or an
organization that is not active, is not allowed. Disabled apps are found too, so a disabled app's client is refused for
everyone. The built-in OAuth provider asks the same question through its `clientAllowed` hook when it redeems codes,
refreshes tokens and answers userinfo, so it refuses people without the app at the token endpoint. Call this, or
`iam.applications.allowed` with the same input and no credential, in your OAuth login or consent page to refuse them
with an explanation before completing the interaction.

```ts
const { allowed } = await iam.applications.allowed({
  tenantId: details.tenantId,
  identityId: identity.id,
  oauthClientId: details.clientId,
});
```

## create

Registers an app in the tenant's catalog: an OAuth client of this deployment, or a link to any tool.

- **Permission:** `iam:applications:manage` on the tenant.
- **Audited as:** `iam:applications:manage`, plus `app:create` with the key and the app's name, launch URL,
  visibility, `enabled`, client and request package.
- **Errors:** `INVALID_INPUT` for a malformed key, a name over 120 characters, a description over 1000, a category
  over 60, a launch or logo URL that is not absolute `https` (or `http` on the local machine, while the deployment
  itself runs there) or carries a user name or password, an `oauthClientId` that is not a live OAuth client of the
  tenant, a package that is not requestable, more than 20 owners, an unknown `visibility` or a non-boolean `enabled`;
  `NOT_FOUND` for an unknown package or owner; `CONFLICT` (409) when an app has the key, or another app already
  governs the `oauthClientId`; `LIMIT_EXCEEDED` (409) past 500 apps.

`key` is permanent: 1 to 64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter.
`launchUrl` is required: the app's sign-in URL, where launching sends the person. `oauthClientId` makes the app `oidc`
(otherwise `link`) and lets it decide who may sign in to that client; one app at most may name a client. `visibility` is `assigned` by default and `enabled` is `true`. `requestPackageId` names a
requestable access package that people without the app may request; it should grant a group the app is assigned to.
`ownerIds` names up to 20 identities to contact about the app and grants them nothing.

```ts
const app = await iam.api.applications.create(credential, {
  tenantId,
  key: 'crm',
  name: 'CRM',
  launchUrl: 'https://crm.example.com/login',
  category: 'Sales',
  oauthClientId: 'crm-web',
  requestPackageId: salesToolsPackageId,
});
```

## delete

Deletes an app with its assignments and launch history.

- **Permission:** `iam:applications:manage` on the app.
- **Audited as:** `iam:applications:manage`, plus `app:delete` with the key and the app's state.
- **Errors:** `NOT_FOUND` when the app is not in this tenant; `CONFLICT` (409) when the app governs an OAuth client
  and `releaseClient: true` is not given.

The assignments go without an `app:unassign` event each. An app with an `oauthClientId` decides who may sign in to
that client, and without it everyone of the organization may, so deleting it needs `releaseClient: true`. To take an
app off every launcher but keep its assignments, and keep refusing its client, set `enabled: false` with
[`update`](#update). The result is `{ deleted: true }`.

```ts
await iam.api.applications.delete(credential, { tenantId, appId, releaseClient: true });
```

## launch

Opens an app the caller has: records the launch and returns the app's launch URL.

- **Permission:** None beyond a person's own signed-in session of the tenant.
- **Audited as:** `app:launch` with the app key.
- **Errors:** `ACCESS_DENIED` (403) when the app is not the caller's (unassigned, disabled, or unknown), and for API
  keys, role sessions, session tokens, delegated sessions, or a session of another tenant;
  `IMPERSONATION_RESTRICTED` (403) while an administrator views as the person.

Each person's launches of an app are kept as one record: the first and last time and how many. The result is
`{ url }`; open it yourself. Launching does not sign the person in to the app: its own sign-in runs as usual. In a
browser, open the tab during the click and point it at the URL once the call returns, since browsers block tabs
opened later.

```ts
const { url } = await client.applications.launch({ tenantId, appId });
```

## list

Lists every app of the tenant by name, with how many live assignments each has and how many people opened it recently.

- **Permission:** `iam:applications:read` on the tenant.
- **Audited as:** `iam:applications:read`.

Disabled apps are included. Each app carries its fields plus `assignments` (assignments that have not ended) and
`launchedLast30Days` (people whose last launch was within 30 days).

## listAssignments

Lists an app's assignments, or every app's, with who they name and when each person last opened the app.

- **Permission:** `iam:applications:read` on the app, or on the tenant when `appId` is left out.
- **Audited as:** `iam:applications:read`.
- **Errors:** `NOT_FOUND` when the app is not in this tenant.

Without `appId`, the result holds the assignments of every app of the tenant (one call for a catalog page). Each
assignment carries `appId`, `subjectType`, `subjectId`, `assignedBy`, `assignedAt`, `expiresAt`, `subjectName` and,
for people, `lastLaunchedAt`, sorted by `subjectName` (else `subjectId`). `subjectName` is the group's name, or the
person's email address or name for callers also allowed `iam:identities:read` on the tenant. It lists every stored
assignment, including ones past their end that the sweep has not removed yet.

## mine

Returns the caller's launcher: the apps they may open now and the apps they may request.

- **Permission:** None beyond a person's own signed-in session of the tenant.
- **Audited as:** Not audited; it only reads.
- **Errors:** `ACCESS_DENIED` (403) for API keys, role sessions, session tokens, delegated sessions, or a session of
  another tenant.

Only enabled apps are listed. An app the person has carries `via` (`everyone`, `direct` or `group`); an app they lack
that names a `requestPackageId` carries that package id instead, for a request through
[`packages.request`](/docs/reference/api/packages#request) (which needs `iam:packages:request` on the package). Each
entry has `id`, `key`, `name`, `description`, `category`, `logoUrl`, and `lastLaunchedAt` once the person opened it.
Apps they have come first, most recently opened first, then by name. In React, `useMyApps` wraps this and `launch`.

## removeUnused

Removes an app's direct assignments to people who have not opened it for `unusedDays`.

- **Permission:** `iam:applications:assign` on the app.
- **Audited as:** `iam:applications:assign`, plus `app:unassign` for each removal, with the reason
  `unused N days`.
- **Errors:** `INVALID_INPUT` for an `unusedDays` outside 7 to 3650; `NOT_FOUND` when the app is not in this tenant.

It removes exactly the assignments [`usage`](#usage) lists as `unused` for the same `unusedDays`. Group assignments
stay. The result is `{ removed }`, the number removed.

```ts
await iam.api.applications.removeUnused(credential, { tenantId, appId, unusedDays: 90 });
```

## unassign

Removes one assignment of an app.

- **Permission:** `iam:applications:assign` on the assignment's app, as for [`assign`](#assign).
- **Audited as:** `iam:applications:assign`, plus `app:unassign` with `subjectType` and `subjectId`, recorded on the
  app.
- **Errors:** `NOT_FOUND` when the assignment is not in this tenant; `CONFLICT` (409) when it changed during the call
  (try again).

The person, or the group's members, lose the app at once unless they have it another way. The result is
`{ removed: true }`.

## update

Changes an app's name, URLs, client, visibility, request package, owners, or whether it is enabled.

- **Permission:** `iam:applications:manage` on the app.
- **Audited as:** `iam:applications:manage`, plus `app:update` with the key and the app's state before and after.
- **Errors:** `INVALID_INPUT` as for [`create`](#create), and when `key` differs from the app's; `NOT_FOUND` when the
  app is not in this tenant; `CONFLICT` (409) when another app already governs the new `oauthClientId`, or when the
  app governs an OAuth client whose `oauthClientId` the call changes or clears without `releaseClient: true`.

Fields you leave out keep their values; `null` or an empty string clears `description`, `category`, `logoUrl`,
`oauthClientId` and `requestPackageId`, and `ownerIds` replaces the whole list. Clearing `oauthClientId` makes the app
a `link` and leaves its former client open to everyone of the organization, so it needs `releaseClient: true`, as
does pointing the app at another client. `enabled: false` takes the app off every launcher and refuses launches, and
sign-ins to its client, while keeping its assignments.

## usage

Reports, per app, how many people have it, how many opened it in 30 days, and the direct assignments nobody uses.

- **Permission:** `iam:applications:read` on the tenant.
- **Audited as:** `iam:applications:read`.
- **Errors:** `INVALID_INPUT` for an `unusedDays` outside 1 to 3650.

Each entry has `appId`, `key`, `name`, `people` (active people who have the app now), `launchedLast30Days` (people
whose last launch was within 30 days), and `unused`: the direct assignments to people made at least `unusedDays` ago
(90 by default) whose person has not opened the app within that time or ever, each with `assignmentId`, `identityId`,
`lastLaunchedAt`, and `name` for callers also allowed `iam:identities:read` on the tenant. Group assignments and
everyone apps are never unused, and disabled apps count no `people`.

```ts
const report = await iam.api.applications.usage(credential, { tenantId, unusedDays: 60 });
```
