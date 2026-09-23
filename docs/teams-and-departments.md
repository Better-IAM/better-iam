# Teams and departments

An organization has two structures besides its groups:

- **Teams** are the working units people belong to: Platform, Site Reliability, the Payments squad. A team can sit
  under another team, has **maintainers** who manage its membership themselves, can take **join requests**, and gives
  its members access through roles bound to it.
- **Departments** are the reporting structure: Engineering, Finance, Sales, and their sub-departments. Each person
  belongs to at most one department, a department can name a **head**, and policies can test where a person sits in the
  org chart.

Both work in any tenant (an organization or a project), and both reach policies through context keys:
`principal.teams`, `principal.departments`, and `principal.departmentId`.

## Teams

### How a team grants access

Every team owns a **backing group** (`team.groupId`, named `team:{slug}`). Bind roles to that group to give the team
access:

```ts
const platform = await iam.api.teams.create(admin, {
  tenantId,
  name: 'Platform',
  description: 'Shared infrastructure and tooling',
  maintainerIds: [bob.id],
});

await iam.api.bindings.create(admin, {
  tenantId,
  roleId: deployer.id,
  subjectType: 'group',
  subjectId: platform.groupId,
});
```

The backing group holds the team's live members **and the members of every team below it**, so a child team's
members receive what is bound to the parent team (as in GitHub's nested teams). Because access flows through an
ordinary group, everything that understands groups understands teams: separation-of-duties rules, invariants, access
reviews, certification campaigns, role mining, `policies.whoCan`, relationships (`subjectType: 'group'`), and
`principal.groups`.

Only the teams module writes the backing group's members. `groups.addMember`, `groups.updateMember`,
`groups.removeMember` and `groups.delete` refuse it with `TEAM_MANAGED` (409), access packages, invitations and
onboarding flows cannot name it, and configuration sync keeps team groups out of its `groups` and `bindings` kinds
(teams have a `teams` kind of their own, see below). `teams.reconcile` recomputes every backing group from team
membership after a restore or repair.

### Nesting

`parentId` places a team under another one, up to ten levels deep. Placing a team under a parent (when creating or
moving it) needs `iam:teams:update` on the parent and the same grant authority as adding someone to the parent's
backing group, because every member of the nested team then receives the parent's access. Moving a team recomputes
the backing groups of the old and the new parents. A team with teams below it cannot be deleted until they are moved or
deleted (`RESOURCE_IN_USE`).

### Members and maintainers

Team members are people (identities of kind `user`); service accounts and agents get access through bindings.
A member is either a `member` or a `maintainer`, and a membership can be temporary (`expiresAt`), ending by itself
like a temporary group membership.

```ts
await iam.api.teams.addMember(admin, {
  tenantId,
  teamId: platform.id,
  identityId: alice.id,
  role: 'member',
  expiresAt: Date.now() + 30 * 86_400_000,
});
await iam.api.teams.addMembers(admin, { tenantId, teamId, identityIds: [carol.id, dave.id] });
await iam.api.teams.updateMember(admin, {
  tenantId,
  teamId,
  identityId: alice.id,
  role: 'maintainer',
});
await iam.api.teams.removeMember(admin, { tenantId, teamId, identityId: alice.id });
```

Administrators need `iam:teams:update` on the team and, like `groups.addMember`, authority over the bindings of the
team's backing group and of every team above it.

**Maintainers** manage membership without an administrator permission: a maintainer of a team, or of any team above
it, may add, update and remove members, find people to add (`teams.candidates`), and decide join requests, from their
own user session. They act under the delegation the team's administrators gave them, so they skip the grant-authority
check, and the operation is audited with `via: team-maintainer`. Separation-of-duties rules and enforced invariants
still apply. A team whose `memberManagement` is `admins` takes membership changes from administrators only.

Maintainers cannot change a team's settings, delete it, or bind roles to it. Whoever binds a role to a team should
keep in mind that the team's maintainers (and those of the teams below it) can hand that role to anyone they add.

Members see their own team: `teams.get` and `teams.listMembers` work for a person who belongs to the team (directly or
through a team below it) without `iam:teams:read`.

### Join requests

A team whose `joinPolicy` is `request` takes join requests. People discover such teams and ask to join from their own
session:

```ts
const mine = await iam.api.teams.listMine(aliceSession, { tenantId });
// mine.teams: the teams Alice is in (with role, expiry and the teams above each one)
// mine.requests: her join requests; mine.joinable: teams that take requests and that she is not in

const request = await iam.api.teams.requestToJoin(aliceSession, {
  tenantId,
  teamId: platform.id,
  justification: 'Joining the on-call rotation',
});
```

The team's maintainers (or, when it has none, those of the nearest team above) receive a `team-join-request` email;
the request lapses after fourteen days. A maintainer or an administrator decides with `teams.approveRequest`
(optionally with `expiresAt` for a temporary membership and a `note`) or `teams.denyRequest`, and the requester gets a
`team-join-decided` email. Nobody decides their own request. `teams.cancelRequest` withdraws a pending request and
`teams.leave` leaves a team.

`TemplateLinks.team` (`renderDeliveryMessage` options) builds the link in both emails; without it they point at
`links.account`.

In React, `useTeams({ tenantId })` from `@better-iam/react` wraps these calls for a "my teams" page (`@better-iam/vue`
has a `useTeams` composable with the same fields as refs). For maintainers, `reviews` lists the open membership
reviews waiting for them:

```tsx
function MyTeams({ tenantId }: { tenantId: string }) {
  const { teams, pending, joinable, requestToJoin, leave } = useTeams({ tenantId });
  return (
    <>
      {teams.map((team) => (
        <Team key={team.id} team={team} onLeave={() => leave(team.id)} />
      ))}
      {joinable.map((team) => (
        <Joinable key={team.id} team={team} onAsk={() => requestToJoin(team.id)} />
      ))}
      {pending.length > 0 && (
        <p>Waiting for a maintainer: {pending.map((r) => r.team.name).join(', ')}</p>
      )}
    </>
  );
}
```

### Team sync from directory groups

A team can take its members from ordinary groups, such as the groups your identity provider pushes over SCIM
(Okta, Microsoft Entra, Google). Name up to ten source groups in `syncGroupIds` (`teams.create` or `teams.update`):

```ts
await iam.api.teams.update(admin, {
  tenantId,
  teamId: platform.id,
  syncGroupIds: [oktaPlatformEngineers.id],
});
```

Everyone with a live membership of a source group (an active person) is then a member of the team, marked
`source: 'sync'`; a temporary source membership makes a temporary team membership that ends with it. People who leave
every source group leave the team. The team follows every change: `groups.addMember`, `groups.updateMember`,
`groups.removeMember`, and each SCIM push of the group (audited with actor `directory-sync`). People added by hand stay
members whatever the groups say, and maintainers remain manual. Synced members cannot be removed from the team (or
given another end) directly (`INVALID_TRANSITION`): change the source group. A source group cannot be deleted while a
team syncs from it (`RESOURCE_IN_USE`), and a team's backing group cannot be a source. `syncGroupIds: null` stops
syncing and removes the synced members. Adding a source needs the same authority as adding members.
`teams.reconcile` runs the sync for every team and then recomputes the backing groups.

### Membership reviews

Teams grow and rarely shrink. A membership review asks a team's maintainers to confirm who still belongs:

```ts
const review = await iam.api.teams.startReview(admin, {
  tenantId,
  teamId: platform.id,
  dueAt: Date.now() + 14 * 86_400_000, // one to 90 days ahead; 14 days by default
  onUndecided: 'remove', // or 'keep' (the default): what happens to people nobody decides on
  note: 'Quarterly access review',
});

// A maintainer, from their own session:
await iam.api.teams.decideReview(bobSession, {
  tenantId,
  reviewId: review.id,
  decisions: [
    { identityId: alice.id, decision: 'keep' },
    { identityId: carol.id, decision: 'remove', note: 'Moved to Sales' },
  ],
});
await iam.api.teams.completeReview(bobSession, { tenantId, reviewId: review.id });
```

- An administrator (`iam:teams:update`) starts a review; every live manual member becomes an item, and the maintainers
  (or, without any, those of the nearest team above) receive a `team-review-requested` email. Members that team sync
  manages are left out: review their source group instead. One review per team is open at a time.
- Maintainers of the team or of a team above, and administrators, decide `keep` or `remove`; a later decision replaces
  an earlier one. Nobody decides on their own membership, so a maintainer's own item waits for another maintainer, a
  maintainer above, or an administrator. `teams.listMine` lists the open reviews waiting for the caller.
- Decisions take effect when the review completes: people decided `remove` leave the team (and lose what it gave them,
  birthright packages included), and people nobody decided on follow `onUndecided`. Maintainers complete a review once
  everyone is decided; administrators may complete it early or `cancelReview` it.
- A review past `dueAt` completes by itself when the scheduler job `iam.closeOverdueTeamReviews()` runs (the console
  runs it hourly). Schedule it in your deployment like `closeOverdueCertifications`.
- `teams.getReview` and `teams.listReviews` show reviews with their decisions and, once complete, the outcome (`kept`,
  `removed`, `undecided`, and `gone` for people who had already left). Removals are audited as `team:member:remove`
  with `source: review`.

### Reading teams

| Method                  | Returns                                                                                                                |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `teams.list`            | Every team with member, maintainer and child counts; filters `parentId` (null for top level), `departmentId`, `query`. |
| `teams.get`             | One team with its path, children, department, maintainers, and the roles its members hold through it or a team above.  |
| `teams.listMembers`     | Live direct members with role and expiry; `includeChildTeams` adds the members of the teams below.                     |
| `teams.listForIdentity` | The teams one person belongs to directly.                                                                              |
| `teams.listRequests`    | Join requests of a team (pending by default).                                                                          |
| `teams.candidates`      | Active people who are not yet direct members, matched by name or email.                                                |

### Helpers for your own code

`@better-iam/server` exports the lookups other modules build on (billing attributes spend to teams with them):

```ts
import { teamsOf, primaryTeamOf, teamMaintainers, isTeamMaintainer } from '@better-iam/server';

await iam.store.transaction(async (tx) => {
  const direct = await teamsOf(tx, tenantId, identityId); // team IDs, oldest membership first
  const all = await teamsOf(tx, tenantId, identityId, { includeAncestors: true });
  const primary = await primaryTeamOf(tx, tenantId, identityId);
  const leads = await teamMaintainers(tx, tenantId, teamId);
  const maintains = await isTeamMaintainer(tx, tenantId, teamId, userId, {
    includeAncestors: true,
  });
});
```

There is no membership history, so attribute things to teams when they happen.

## Departments

### The org chart

```ts
const engineering = await iam.api.departments.create(admin, {
  tenantId,
  name: 'Engineering',
  code: 'ENG',
  headId: alice.id,
  costCenter: 'CC-100',
});
const platformDept = await iam.api.departments.create(admin, {
  tenantId,
  name: 'Platform',
  code: 'ENG-PLT',
  parentId: engineering.id,
  headId: bob.id,
});

await iam.api.departments.assign(admin, {
  tenantId,
  departmentId: platformDept.id,
  identityIds: [carol.id, erin.id],
  title: 'Engineer',
});
```

Names and codes are unique per tenant (ignoring case); departments nest up to twenty levels. A person belongs to one
department at a time, so `assign` moves people who were elsewhere. A team can name the department it belongs to
(`teams.create/update({ departmentId })`).

Reading needs `iam:departments:read`: `departments.list` (flat, with member counts including sub-departments),
`departments.tree` (the org chart with heads), `departments.get`, `departments.listMembers` (`includeSubdepartments`),
and `departments.ofIdentity` (a person's department with the path above it). Changing the structure and placing people
needs `iam:departments:manage`. Deleting a department unassigns its people and unfiles its teams; a department with
sub-departments cannot be deleted (`RESOURCE_IN_USE`).

### Your own place in it

`departments.mine` needs only a person's own session: it returns their department (with the path from the top, their
title, and their head) and, for department heads, the people of every department they head and of the departments
below. Managers get a view of their organization without `iam:departments:read`; the console shows it as "Your
department" and "People you lead".

### Importing from HR data

Directories and HR systems usually send a department name with each person (SCIM's enterprise `department`, or an
attribute your onboarding flow fills). `departments.importFromAttribute` places everyone whose string identity
attribute names a department (by name or code, ignoring case):

```ts
const preview = await iam.api.departments.importFromAttribute(admin, {
  tenantId,
  attribute: 'department', // declared in permissions.identityAttributes as a string
  createMissing: true, // create top-level departments for values nothing matches
  dryRun: true,
});
// { created: ['Sales'], assigned: 12, unchanged: 30, unmatched: [], missing: 2 }
```

### Managers from the org chart

`departments.syncManagers` makes department heads the managers (`Identity.managerId`) of their departments' people:
each person reports to the head of their department, a head to the nearest head above. Approvals routed to managers
(`managerApproval` on eligible bindings and access packages, `reviewerMode: 'manager'` in certification campaigns) then
follow the org chart. Without `overwrite` only people without a manager change; `departmentId` limits the run to one
branch; `dryRun` reports only. It needs `iam:identities:update` and `iam:departments:read`, and never creates a cycle.

### Helpers for your own code

```ts
import { departmentOf, departmentPath, departmentHeads } from '@better-iam/server';

await iam.store.transaction(async (tx) => {
  const departmentId = await departmentOf(tx, tenantId, identityId);
  const path = await departmentPath(tx, tenantId, departmentId!); // top first, ending with the department
  const heads = await departmentHeads(tx, tenantId, departmentId!, { includeAncestors: true });
});
```

## Policies

| Key                      | Type       | Value                                                                         |
| ------------------------ | ---------- | ----------------------------------------------------------------------------- |
| `principal.teams`        | list       | IDs of the teams the person belongs to directly and of every team above them. |
| `principal.departments`  | list       | The person's department ID and the IDs of every department above it.          |
| `principal.departmentId` | identifier | The person's own department; absent without one.                              |

The keys describe people in their own organization; assumed roles see empty lists. They are read only when a policy
names them, so they cost nothing otherwise.

```json
{
  "version": 1,
  "statements": [
    {
      "sid": "EngineeringReadsDesignDocs",
      "effect": "allow",
      "actions": ["documents:read"],
      "resources": ["document/*"],
      "conditions": {
        "ArrayContains": { "principal.departments": ["<engineering department id>"] }
      }
    },
    {
      "sid": "OwnDepartmentWrites",
      "effect": "allow",
      "actions": ["documents:write"],
      "resources": ["document/*"],
      "conditions": { "StringEquals": { "principal.departmentId": "${resource.departmentId}" } }
    }
  ]
}
```

Identity attributes cannot use the names `teams`, `departments`, or `departmentId`.

## Birthright access by team or department

[Automatic access packages](policies.md#automatic-assignment-birthright) can follow the org structure. Their rules may
test two more keys: `identity.teams` (the teams a person belongs to and every team above them) and
`identity.departments` (their department and every department above it), both by ID.

```ts
await iam.api.packages.create(credential, {
  tenantId,
  name: 'Engineering basics',
  groupIds: [wikiGroupId],
  autoAssign: {
    include: [
      {
        StringEquals: { 'principal.kind': 'user' },
        ArrayContains: { 'identity.departments': engineeringId },
      },
      {
        StringEquals: { 'principal.kind': 'user' },
        ArrayContains: { 'identity.teams': sreTeamId },
      },
    ],
  },
});
```

- **Joiners, movers, and leavers.** Placing someone in a department or team (through `departments.assign`,
  `importFromAttribute`, `teams.addMember(s)`, an approved join request, …) gives them the package at once; moving
  them, moving their department or team elsewhere in the tree, or removing them takes it away (after the rule's
  grace period, if any). Changes that arrive another way (team sync from SCIM groups, configuration apply, expiring
  memberships) take effect at the next scheduled reconcile.
- **No chains.** A team membership that team sync copied from a group counts only while the person is in that group
  by a membership no access package created, so a package can never grant itself through a team.
- **Referential safety.** A team or department a rule names cannot be deleted (`RESOURCE_IN_USE`, listing the
  packages) until the rule stops naming it; neither can a team whose backing group a rule tests under
  `identity.groups`. Unknown IDs fail the save with `INVALID_INPUT`.
- **Configuration as code.** Documents name teams by slug and departments by name in these rules; teams and
  departments are created before packages are saved and deleted after, so one document can introduce both.
- **Console.** Team and department pages list the packages whose rules name them or a team or department above
  them (for readers of `iam:packages:read`); the Access packages page lists team and department IDs next to the
  group IDs.

Onboarding flow rules use the same language but not these two keys.

### Suggestions from the access people already hold

`departments.suggestBirthright` and `teams.suggestBirthright` (`iam:analysis:read`) look at what people already hold
by hand and propose the packages above: for each department (or team) with at least `minPeople` (3) people, the roles
and groups at least `minShare` (80%) of them hold directly, as a `package` ready for `packages.create`:

```ts
for (const suggestion of await iam.api.departments.suggestBirthright(admin, { tenantId })) {
  console.log(suggestion.unit.name, suggestion.roles, suggestion.groups, suggestion.wouldGrant);
}
const [engineering] = await iam.api.departments.suggestBirthright(admin, {
  tenantId,
  departmentId: engineeringId,
});
await iam.api.packages.create(admin, { tenantId, ...engineering!.package });
```

A department counts the people below it, which is exactly who the suggested rule matches. Only plain grants count
(standing, permanent bindings made to the person, and permanent memberships of ordinary groups, none from a package),
and nothing is suggested twice: not what is suggested for a department or team above, not what an automatic package
naming it already grants, and not what most of its people already receive from any automatic package. Creating the
package leaves the hand-made grants in place; remove them once the package holds, so access follows the org chart.
The console shows the suggestions on the Departments page and on each department and team page, with a "Create
package" button.

## Configuration as code

`config.export`, `config.plan`, and `config.apply` (and the `config-*` CLI commands) include two kinds, each only when
the tenant has some:

```json
{
  "version": 1,
  "departments": [
    {
      "name": "Engineering",
      "code": "ENG",
      "head": "alice@acme.test",
      "members": ["alice@acme.test"]
    },
    { "name": "Platform", "parent": "Engineering", "head": "bob@acme.test", "costCenter": "CC-7" }
  ],
  "teams": [
    {
      "name": "Platform",
      "slug": "platform",
      "department": "Platform",
      "joinPolicy": "request",
      "maintainers": ["bob@acme.test"],
      "members": ["alice@acme.test"],
      "roles": ["Deployer"]
    },
    { "name": "Site Reliability", "slug": "sre", "parent": "platform" }
  ]
}
```

Teams are matched by `slug` and departments by name (ignoring case); people are named by email and roles by name.
When a team lists `maintainers` or `members`, its permanent manual members are made to match exactly (temporary and
synced memberships and join requests are runtime state and left alone; naming a synced person makes them a manual
member); `roles` makes the team's standing role bindings match, and `syncGroups` (group names) sets team sync. Department `members` works the same way. Parents and departments may come from the document or the tenant;
unknown people, roles, parents, and cycles fail the plan with `INVALID_INPUT`. Apply creates parents before children
and, with `prune`, deletes children before parents, each change authorized like the equivalent API call. Team backing
groups never appear under `groups` or `bindings`.

## Access analysis

`analysis.findings` reports teams whose maintainers can make anyone a full administrator (the team or a team above it
holds an administrator role as standing access and maintainers manage its membership: `team-maintainers-grant-admin`,
high), teams with members but no active maintainer (`team-without-maintainer`, low), and departments with people but
no active head (`department-without-head`, low). The console's Security findings page links them to the team or
department.

## Offboarding and deletion

`identities.offboard` removes the person from every team (reported as `teamsLeft`) and hands the departments they
head to the successor (`departmentsReassigned`); both counts appear only when non-zero. `identities.delete` ends team
memberships and department placement and clears the departments the person headed.

## Audit

Team events: `team:create`, `team:update`, `team:delete`, `team:member:add`, `team:member:update`,
`team:member:remove`, `team:join:request`, `team:join:approve`, `team:join:deny`, `team:join:cancel`, `team:leave`
(maintainer actions carry `via: maintainer`). Department events: `department:create`, `department:update`,
`department:delete`, `department:assign`, `department:unassign`, `department:sync-managers`. Every operation is also
recorded under its `iam:teams:*` or `iam:departments:*` action like any other call.

## Console

The cloud console has **Teams** (your teams and join requests, all teams as a tree, create) and **Departments** (org
chart, create, import from attributes, managers from the org chart) under Directory, with a page per team and per
department. Maintainers see their team's page with the membership tools only. Member pages show a person's teams and
department, and team-backed groups are marked on the Groups page.
