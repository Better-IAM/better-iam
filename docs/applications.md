# Application catalog and My apps

The application catalog is the list of tools an organization gives its people, and **My apps** is the launcher where
each person finds the ones they have and opens them with one click. An application is either an OpenID Connect client
of this deployment (an OAuth client registered with the [authorization server](protocols.md#oauthoidc-authorization-server))
or a plain link to any other tool.

Administrators decide who has each app: **everyone** in the organization, or only the people and groups it is
**assigned** to, optionally until a date. People who lack an app can **request** it through an
[access package](privileged-access.md#access-packages). Every launch is recorded and audited, usage shows which direct
assignments nobody uses, and the OAuth provider **refuses** tokens to people who do not have the app.

Everything lives in the `applications` API group (`POST /api/iam/applications/{method}`, `client.applications.*` in
the browser). The built-in OAuth provider enforces assignments for `oidc` apps by itself, and a deployment's own
sign-in pages check access with `iam.applications.allowed(...)`.

```ts
// Register an app and give it to a group.
const crm = await iam.api.applications.create(admin, {
  tenantId,
  key: 'crm',
  name: 'CRM',
  launchUrl: 'https://crm.acme.test/login',
  category: 'Sales',
});
await iam.api.applications.assign(admin, {
  tenantId,
  appId: crm.id,
  subjectType: 'group',
  subjectId: sales.id,
});

// A person's launcher, from their own session.
const apps = await iam.api.applications.mine(aliceSession, { tenantId });

// Opening one records the launch and returns where to go.
const { url } = await iam.api.applications.launch(aliceSession, { tenantId, appId: crm.id });
```

## Applications

An application (`create`, `iam:applications:manage`) has these fields:

| Field              | Meaning                                                                                                                                                                                                                                                                   |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `key`              | A permanent identifier, unique in the tenant: 1 to 64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter.                                                                                                                                    |
| `name`             | Up to 120 characters.                                                                                                                                                                                                                                                     |
| `description`      | Up to 1000 characters, shown on the launcher.                                                                                                                                                                                                                             |
| `category`         | Up to 60 characters. The console's launcher groups apps by category.                                                                                                                                                                                                      |
| `launchUrl`        | Required. Where launching sends the person: the app's sign-in URL.                                                                                                                                                                                                        |
| `logoUrl`          | An image shown next to the app's name.                                                                                                                                                                                                                                    |
| `oauthClientId`    | The `clientId` of an OAuth client of this organization, for an app that signs people in through this deployment. It must exist and not be revoked, and only one app may name it: the app then [decides who may sign in](#enforcing-assignments-at-sign-in) to the client. |
| `kind`             | Set for you: `oidc` when the app names an `oauthClientId`, `link` otherwise.                                                                                                                                                                                              |
| `visibility`       | `assigned` (the default): only assigned people and members of assigned groups have the app. `everyone`: every active person of the organization has it.                                                                                                                   |
| `enabled`          | `true` by default. A disabled app disappears from every launcher and cannot be launched; its assignments stay.                                                                                                                                                            |
| `requestPackageId` | A requestable [access package](#requesting-an-app) people without the app may ask for.                                                                                                                                                                                    |
| `ownerIds`         | Up to 20 identities of the tenant to contact about the app. Being an owner grants nothing.                                                                                                                                                                                |

Launch and logo URLs are absolute `https` URLs of up to 2048 characters, and cannot carry a user name or password.
While the deployment itself runs on `localhost`, `127.0.0.1` or `[::1]` (its `baseURL`), they may also be `http` on
those hosts, for development. A tenant holds at most 500 apps.

`update` changes any field but the key. Fields you leave out keep their values; `null` or an empty string clears
`description`, `category`, `logoUrl`, `oauthClientId` and `requestPackageId`, and `ownerIds` replaces the whole list.
Clearing `oauthClientId` makes the app a `link`. `delete` removes the app with its assignments and launch history.

An app that names an `oauthClientId` governs that client: without the app, everyone of the organization may sign in to
it. So changing or clearing its `oauthClientId`, or deleting it, needs `releaseClient: true`, and answers `CONFLICT`
without it. To keep refusing everyone, disable the app instead (`enabled: false`).

```ts
await iam.api.applications.delete(admin, { tenantId, appId: crm.id, releaseClient: true });
```

Creating, changing and deleting apps are audited as `app:create`, `app:update` (with the state before and after) and
`app:delete`.

`list` (`iam:applications:read`) returns every app of the tenant by name, disabled ones included, each with
`assignments` (how many assignments have not ended) and `launchedLast30Days` (how many people last opened it within 30
days).

## Who has an app

A person has an app when the app is enabled and one of these holds:

- its visibility is `everyone`;
- it is assigned to them, and the assignment has not ended;
- it is assigned to a group they are a member of, and neither the assignment nor the membership has ended.

Only active, unexpired people have apps: service accounts, agents, and disabled, expired or deleted accounts have none.
The launcher tells the person why they have each app (`via`): `direct` when it is assigned to them, else `group`,
else `everyone`.

Assignments are kept whatever the visibility, so switching an app from `everyone` to `assigned` leaves exactly the
assigned people and groups with it. Deleting a person removes their assignments and launch history and takes them off
every app's `ownerIds`; deleting a group removes its assignments.

## Assignments

`assign` (`iam:applications:assign` on the app) gives an app to a person or a group:

```ts
await iam.api.applications.assign(admin, {
  tenantId,
  appId: crm.id,
  subjectType: 'identity',
  subjectId: contractorId,
  expiresAt: Date.parse('2026-12-31T00:00:00Z'),
});
```

- `subjectType` is `identity` (a person of the tenant; service accounts and agents are refused) or `group`.
- `expiresAt` is optional: in the future, at most ten years away. Without it the assignment lasts until it is removed.
- Assigning the same person or group again replaces the assignment, with the new `expiresAt` (none when left out) and
  the caller and time as `assignedBy` and `assignedAt`.
- An app holds at most 10,000 assignments (`LIMIT_EXCEEDED`): assign groups instead.
- Each assignment is audited as `app:assign`.

`unassign` removes one assignment by its id (`iam:applications:assign` on the assignment's app, like `assign`) and is
audited as `app:unassign`. `listAssignments` (`iam:applications:read`) lists an app's assignments, or every app's when
`appId` is left out, by name, each with `subjectName` and, for people, `lastLaunchedAt`. `subjectName` is the group's
name, or the person's email address or name for callers who may read the directory (`iam:identities:read` on the
tenant). It lists every stored assignment, including ones past their end that the sweep has not removed yet.

An assignment stops counting the moment it ends, and `iam.sweepExpired()` deletes it afterwards.

## Requesting an app

Give an app a `requestPackageId` to let people without it ask for it. The package must belong to the tenant and be
requestable, and it should grant a group the app is assigned to; the catalog does not check that part.

People who do not have the app then see it in their launcher with `requestPackageId` and without `via`, and request
it with [`packages.request`](privileged-access.md#access-packages), which needs `iam:packages:request` on the package.
The package's approvers decide as for any package request. Once the person is in the group, the app is theirs.

```ts
const pkg = await iam.api.packages.create(admin, {
  tenantId,
  name: 'Sales tools',
  groupIds: [sales.id],
  requestable: true,
});
await iam.api.applications.update(admin, { tenantId, appId: crm.id, requestPackageId: pkg.id });

// Bob, without the CRM:
await iam.api.packages.request(bobSession, {
  tenantId,
  packageId: pkg.id,
  justification: 'Covering accounts while Alice is away',
});
```

Apps a person already has never carry `requestPackageId`, and disabled apps are not offered.

## The launcher

People use the launcher from their own signed-in session of the organization, without any permission. API keys, role
sessions, session tokens, delegated sessions and sessions of another organization are refused (`ACCESS_DENIED`).

`mine` returns the person's apps: every enabled app they have, then every enabled app they could request. Each entry
carries `id`, `key`, `name`, `description`, `category`, `logoUrl`, `via` (for apps they have), `requestPackageId` (for
apps they may request) and `lastLaunchedAt` once they opened it. Apps they have come first, most recently opened
first, then by name. `mine` is not audited.

`launch` opens an app the person has now:

- it records the launch (per person and app: the first and last time, and how many times);
- it audits `app:launch` with the app's key;
- it returns `{ url }`, the app's launch URL, for the caller to open.

An app the person does not have (unassigned, disabled or unknown) answers `ACCESS_DENIED`. Launching does not sign
the person in to the app: the app's own sign-in runs as usual, through this deployment for `oidc` apps. An
administrator [viewing as the person](authentication.md#impersonation) sees their launcher, but `launch` answers
`IMPERSONATION_RESTRICTED` (403): opening the app would count as the person's use and start a sign-in in their name.

In React, `useMyApps({ tenantId, enabled? })` from `@better-iam/react` loads the launcher. `apps` holds the apps the
person can open (most recently used first), `requestable` those they may request, `status`, `error` and `refresh`
work as in the other hooks, and `launch(appId)` records the launch, reloads, and resolves to the URL to open. The hook
does not open the app for you. Because `launch` resolves only after a round trip, a tab opened then is no longer a
direct result of the click and browsers block it: open the tab during the click, then point it at the app, and close
it if the launch is refused:

```tsx
function Launcher({ tenantId }: { tenantId: string }) {
  const { apps, requestable, launch } = useMyApps({ tenantId });
  async function open(appId: string) {
    // Open the tab during the click (browsers block tabs opened later), then point it at the app.
    const tab = window.open('about:blank', '_blank');
    try {
      const url = await launch(appId);
      if (tab) {
        tab.opener = null;
        tab.location.href = url;
      } else window.location.href = url;
    } catch (error) {
      tab?.close(); // not the person's app, or an administrator viewing as them
      throw error;
    }
  }
  return (
    <>
      {apps.map((app) => (
        <button key={app.id} onClick={() => void open(app.id)}>
          {app.name}
        </button>
      ))}
      {requestable.map((app) => (
        <RequestAccessButton key={app.id} packageId={app.requestPackageId!} />
      ))}
    </>
  );
}
```

`RequestAccessButton` stands for your own component that calls `packages.request` with the package id.

## Enforcing assignments at sign-in

The launcher shows people their apps, but it does not stop anyone from going to an app directly. For `oidc` apps, the
deployment's [authorization server](protocols.md#oauthoidc-authorization-server) does. `iam.protocolHost` supplies
the OAuth provider's optional hook `clientAllowed(identityId, tenantId, clientId)`, so a provider created with
`createOAuthProvider({ ...iam.protocolHost, ... })` asks the catalog whenever it loads a person's account for a client:
when it redeems an authorization code, refreshes tokens, and answers userinfo. A person without the app gets no tokens
for its client, and removing someone's app, or disabling it, also stops their refresh tokens. A provider configured
without `iam.protocolHost` can pass a `clientAllowed` of its own; without one it enforces nothing.

The provider refuses at the token endpoint, after the person has signed in, so the app sees a failed token request.
To tell the person why instead, check in your interaction page before completing it:

```ts
const details = await issuer.interactionDetails(req, res);
const { identity } = await iam.authenticate(credential);
const access = await iam.applications.allowed({
  tenantId: details.tenantId,
  identityId: identity.id,
  oauthClientId: details.clientId,
});
if (!access.allowed) {
  // Not assigned: show a "request access" page, or end the flow with access_denied.
  await issuer.completeInteraction(req, res, { credential, consent: false });
  return;
}
```

`iam.applications.allowed({ tenantId, identityId, appId? | oauthClientId? })` takes exactly one of `appId` and
`oauthClientId` and answers `{ allowed, governed, appId? }`:

- An `oauthClientId` no app in the catalog names is not governed here: `{ allowed: true, governed: false }`. Only
  clients registered as apps are enforced.
- For an app, `governed` is `true` with its `appId`, and `allowed` says whether the person has the app now, under the
  [rules above](#who-has-an-app). An identity that does not exist or belongs to another tenant, or an organization that
  is not active, is not allowed.
- The lookup includes disabled apps, so a disabled app's client is refused for everyone rather than left ungoverned.
- An unknown `appId` answers `NOT_FOUND`; naming both or neither answers `INVALID_INPUT`.

`iam.applications.allowed` takes no credential and is not audited: it is for the deployment's own code, and answers
what the provider's `clientAllowed` hook does. The same check over the API is `check` (`iam:applications:read` on the
tenant), audited as `iam:applications:read`.

## Usage and unused assignments

`usage` (`iam:applications:read`) returns, for every app by name:

- `people`: how many active people have the app now;
- `launchedLast30Days`: how many people last opened it within 30 days;
- `unused`: the direct assignments to people made at least `unusedDays` ago whose person has not opened the app within
  `unusedDays`, or never has, each with `assignmentId`, `identityId`, `lastLaunchedAt`, and `name` for callers who
  may read the directory.

`unusedDays` is 90 by default (1 to 3650). Group assignments and everyone apps are never listed as unused.

`removeUnused` (`iam:applications:assign` on the app) removes those direct assignments of one app for `unusedDays` (7
to 3650, required) and returns `{ removed }`. Group assignments stay. Each removal is audited as `app:unassign` with
the reason `unused {days} days`.

```ts
const report = await iam.api.applications.usage(admin, { tenantId, unusedDays: 60 });
for (const app of report.filter((item) => item.unused.length))
  await iam.api.applications.removeUnused(admin, { tenantId, appId: app.appId, unusedDays: 60 });
```

## Retention

Apps and their assignments stay until you delete them, except that `iam.sweepExpired()` deletes assignments past
their end. Launch records (one per person and app) stay with the app. `delete` removes an app's assignments and launch
records with it; deleting a person removes theirs, and deleting a group its assignments. All three collections
(`applications`, `appAssignments`, `appLaunches`) are removed with their organization.

## Permissions

| Action                    | Methods                                     |
| ------------------------- | ------------------------------------------- |
| `iam:applications:read`   | `list`, `listAssignments`, `usage`, `check` |
| `iam:applications:manage` | `create`, `update`, `delete`                |
| `iam:applications:assign` | `assign`, `unassign`, `removeUnused`        |
| none (own session)        | `mine`, `launch`                            |

Actions are checked on the tenant (`iam/{tenantId}`) for `create`, `list`, `usage`, `check` and `listAssignments`
without `appId`, and on the app (`iam/{appId}`) for `update`, `delete`, `assign`, `listAssignments`, `removeUnused`
and `unassign` (the assignment's app). People's names and email addresses appear in `listAssignments` and `usage` only
for callers who may also read the directory (`iam:identities:read` on the tenant). A typical split gives IT administrators `iam:applications:manage` and `iam:applications:assign`, app owners
or helpdesk staff `iam:applications:assign` on their apps, and auditors `iam:applications:read`.

## Audit events

Every method that requires an `iam:applications:*` action records it (outcome `allow` or `deny`) like any operation;
`mine` is not audited. These events record what happened, subscribable as `app:*`:

| Event          | Recorded when                                                             | Resource | Metadata                                                                                             |
| -------------- | ------------------------------------------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------- |
| `app:create`   | `create` registered an app                                                | The app  | `key`, `name`, `launchUrl`, `visibility`, `enabled`, `oauthClientId` and `requestPackageId` (if set) |
| `app:update`   | `update` changed an app                                                   | The app  | `key`, `before`, `after` (the fields `app:create` records)                                           |
| `app:delete`   | `delete` removed an app                                                   | The app  | `key` and the fields `app:create` records                                                            |
| `app:assign`   | `assign` gave the app to a person or group                                | The app  | `key`, `subjectType`, `subjectId`, `expiresAt` (if set)                                              |
| `app:unassign` | `unassign` removed an assignment, or `removeUnused` removed an unused one | The app  | `subjectType`, `subjectId`, `reason` (`removeUnused`)                                                |
| `app:launch`   | A person opened the app from their launcher                               | The app  | `key`                                                                                                |

Deleting an app, a person or a group removes assignments without recording `app:unassign` for each.

## Errors

| Code                             | When                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `INVALID_INPUT`                  | A malformed or changed key; a name, description or category too long; a launch or logo URL that is not absolute `https` (or local `http` on a local deployment) or carries credentials; an `oauthClientId` that is not a live OAuth client of the organization; a package that is not requestable; more than 20 owners; an unknown `visibility`, `subjectType` or non-boolean `enabled`; assigning a service account or agent; an `expiresAt` not in the future or more than ten years away; `unusedDays` out of range; `check` naming both or neither of `appId` and `oauthClientId`. |
| `CONFLICT` (409)                 | An app with the key exists; another app already governs the OAuth client; deleting an app that governs an OAuth client, or changing or clearing its `oauthClientId`, without `releaseClient: true`.                                                                                                                                                                                                                                                                                                                                                                                    |
| `LIMIT_EXCEEDED` (409)           | The tenant would have more than 500 apps, or the app more than 10,000 assignments.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `NOT_FOUND` (404)                | An unknown app, assignment, group, person, owner or access package, a deleted person, or `check` with an unknown `appId`.                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `ACCESS_DENIED` (403)            | The caller lacks the `iam:applications:*` action; `mine` or `launch` from anything but a person's own session of the organization; `launch` of an app the person does not have.                                                                                                                                                                                                                                                                                                                                                                                                        |
| `IMPERSONATION_RESTRICTED` (403) | `launch` while an administrator views as the person.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |

## Console

- **Home › My apps**: the person's apps grouped by category (apps without one under "Apps"), each with its logo,
  description, an Open button that records the launch and opens the app in a new tab, and when they last opened it
  ("new" before the first time). Apps they may request are listed under "More apps" with a Request access button,
  which asks why they need it and requests the package.
- **Access › Applications**: every app with its key, visibility, an OIDC badge for OAuth clients, its launch URL, how
  many people have it and how many opened it in 30 days, and Enable/Disable and Delete buttons (Delete asks first, and
  for an app that governs an OAuth client warns that everyone may then sign in to it, and releases it); its
  assignments (who, until when, last opened) with a Remove button each; the direct assignments unused for 90 days with a Remove unused
  button; forms to assign it to a group or a person, optionally until a date; and a form to add an application.
