# departments

Departments are the organization's reporting structure: Engineering, Finance, Sales, and their sub-departments. Each
person belongs to at most one department, a department can name a head, a code, and a cost center, and teams can be
filed under a department. Teams, the working units, are the [`teams`](/docs/reference/api/teams) group.

## Departments in policies

Every evaluation for a person in their own tenant can read two [condition](/docs/guides/authorization/conditions)
keys, loaded only when a policy names them:

- `principal.departments`: the person's department ID and the IDs of every department above it.
- `principal.departmentId`: the person's own department; absent without one.

```json
{
  "effect": "allow",
  "actions": ["documents:write"],
  "resources": ["*"],
  "conditions": { "StringEquals": { "principal.departmentId": "${resource.departmentId}" } }
}
```

`{ "ArrayContains": { "principal.departments": ["<engineering id>"] } }` admits everyone in Engineering and its
sub-departments. Sessions of an assumed role see an empty list.

## Managers from the org chart

`syncManagers` sets each person's manager (`managerId`) to the head of their department, and a head's to the nearest
head above. Approvals routed to managers (eligible bindings and access packages with `managerApproval`, certification
campaigns with `reviewerMode: 'manager'`) then follow the org chart.

## Birthright packages

[Access package rules](/docs/guides/privileged-access/automatic-assignment) may test `identity.departments`: a
person's department ID and the IDs of the departments above it. `assign`, `unassign`, `importFromAttribute`, moving or
deleting a department, and `syncManagers` (rules may test `identity.managerId`) re-evaluate the rules for the people
they touch once they commit: joiners get their department's packages at once, and movers and leavers lose them.

## assign

Places up to 100 people (`identityIds`, or one `identityId`) in a department, moving them out of any other, with an
optional `title`. Returns how many changed.

- **Permission:** `iam:departments:manage` on `iam/{departmentId}`.
- **Audited as:** `iam:departments:manage` and `department:assign` per person (`previousDepartmentId` when moved).
- **Errors:** `INVALID_INPUT` for a service account or agent, or without people; `NOT_FOUND`.

## create

Creates a department, optionally under `parentId`, with a `code`, a `headId` (an active person of the organization), a
`costCenter`, and a `description`.

- **Permission:** `iam:departments:manage` on the tenant.
- **Audited as:** `iam:departments:manage` and `department:create`.
- **Errors:** `CONFLICT` (409) when the name or code (ignoring case) is taken; `INVALID_INPUT` for a bad code, a head
  who is not a person, or more than twenty levels of nesting; `LIMIT_EXCEEDED` past 2000 departments.

```ts
const engineering = await iam.api.departments.create(credential, {
  tenantId,
  name: 'Engineering',
  code: 'ENG',
  headId,
  costCenter: 'CC-100',
});
```

## delete

Deletes a department. Its people become unassigned and its teams lose the link.

- **Permission:** `iam:departments:manage` on the department.
- **Audited as:** `iam:departments:manage` and `department:delete` (`unassigned`, `teams`).
- **Errors:** `RESOURCE_IN_USE` (409) while departments sit below it, or while an access package rule names it
  (`identity.departments`).

## get

One department with its path (the departments above it), sub-departments, head, and teams, and member counts with and
without the departments below.

- **Permission:** `iam:departments:read` on the department.

## importFromAttribute

Places every active person whose string identity attribute (such as `department`, filled by SCIM provisioning or an
onboarding form) names a department, matched by name or code ignoring case. `createMissing` creates top-level
departments for values nothing matches; `dryRun` reports without changing anything.

- **Permission:** `iam:departments:manage` on the tenant.
- **Audited as:** `iam:departments:manage`, and `department:create` / `department:assign` for what changed.
- **Errors:** `INVALID_INPUT` when the attribute is not a declared string identity attribute.

```ts
const result = await iam.api.departments.importFromAttribute(credential, {
  tenantId,
  attribute: 'department',
  createMissing: true,
  dryRun: true,
});
// { dryRun: true, created: ['Sales'], assigned: 12, unchanged: 30, unmatched: [], missing: 2 }
```

## list

Every department with member counts (with and without sub-departments), child and team counts, in name order.

- **Permission:** `iam:departments:read` on the tenant.

## listMembers

The people of a department, heads first; `includeSubdepartments` adds those of every department below, each with their
department. Each entry carries the person's title, since when they are in the department, and their manager.

- **Permission:** `iam:departments:read` on the department.

## mine

Your own place in the org chart and, if you head departments, the people you lead.

- **Permission:** None beyond an ordinary session (or API key) of a person in the organization.
- **Audited as:** Not audited; it only reads.
- **Errors:** `ACCESS_DENIED` for a service account, an agent, a temporary credential, or another tenant's session.

`department` is your department with the path from the top, your title, since when, its head, and its cost center
(null without a department). `leads` lists each department you head with its people and those of every department
below it (name, email, department, title, and manager), heads first. Use it for a "my team" page that managers can
open without `iam:departments:read`.

## ofIdentity

A person's department with the path from the top, their title, since when, the department's head and cost center; null
when they have none.

- **Permission:** `iam:departments:read` on `iam/{identityId}`.

## suggestBirthright

Roles and groups that most of a department's people already hold by hand, proposed as a ready-made automatic access
package whose rule names the department.

- **Permission:** `iam:analysis:read` on the tenant.
- **Audited as:** Not audited; it only reads.
- **Errors:** `INVALID_INPUT` for `minShare` outside 0.5-1; `NOT_FOUND` for an unknown `departmentId`.

A department's people are exactly who a rule naming it would match: active people placed in it or in a department
below it. Only plain grants count (standing, permanent role bindings made to the person and permanent memberships of
ordinary groups, none from an access package), an item must be held by at least `minShare` (default 0.8) of at least
`minPeople` (default 3) people, and nothing is suggested twice: not what is suggested for a department above, not
what an automatic package naming the department (or one above) grants, and not what most of the department already
receives from any automatic package. Each suggestion carries the shares, `wouldGrant` (people who would gain
something), `existingPackages`, and `package`, ready for [`packages.create`](/docs/reference/api/packages#create):

```ts
const [suggestion] = await iam.api.departments.suggestBirthright(credential, {
  tenantId,
  departmentId: engineeringId,
});
if (suggestion) await iam.api.packages.create(credential, { tenantId, ...suggestion.package });
```

## syncManagers

Makes department heads the managers of their departments' people (see above). Without `overwrite` only people without
a manager change; `departmentId` limits the run to one department and those below it; `dryRun` reports only. Returns
the changes with names, how many kept another manager, and how many had no head above them. Never creates a cycle.

- **Permission:** `iam:identities:update` on the tenant (or the department) and `iam:departments:read`.
- **Audited as:** `iam:identities:update` and `department:sync-managers`.

## tree

The org chart: top-level departments with their sub-departments, heads, and member counts.

- **Permission:** `iam:departments:read` on the tenant.

## unassign

Takes a person out of their department.

- **Permission:** `iam:departments:manage` on `iam/{identityId}`.
- **Audited as:** `iam:departments:manage` and `department:unassign`.
- **Errors:** `NOT_FOUND` when the person has no department.

## update

Renames, re-codes, moves (`parentId`, null for top level), or changes the head, cost center, or description of a
department; null (or an empty string) clears an optional field.

- **Permission:** `iam:departments:manage` on the department.
- **Audited as:** `iam:departments:manage` and `department:update` (`fields`).
- **Errors:** `INVALID_INPUT` when moving under itself or a department below it, or past twenty levels; `CONFLICT` for
  a taken name or code.
