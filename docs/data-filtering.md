# Data filtering

`authorize` answers "may this person read document 42?". A list page needs a different answer: "which documents may
this person read?", ideally as part of the database query, so the application does not fetch every row and check each
one. Better IAM answers that with a **query plan**: the policy engine evaluates everything it already knows (the
action, the person's roles, groups, attributes, session and tenant) and hands back what is left as a filter over the
resource's `id` and attributes. You compile the filter into your own query.

```ts
import { filterToSql } from 'better-iam/core';

const plan = await iam.planResources({
  headers: request.headers, // or { token }
  tenantId,
  action: 'documents:read',
  type: 'document',
});

if (plan.kind === 'never') return [];
const where = filterToSql(plan.filter, {
  dialect: 'postgres',
  column: (field) => ({ id: 'd.id', ownerId: 'd.owner_id', classification: 'd.classification' })[field],
});
const rows = await db.query(`SELECT * FROM documents d WHERE d.tenant_id = $1 AND ${where.sql}`, [
  tenantId,
  ...where.params,
]);
```

This is partial evaluation, the idea behind Cerbos `PlanResources` and OPA's partial evaluation. The plan has the
engine's semantics: a resource passes the filter exactly when `authorize` would allow it. The one exception is a
decision refused because it exceeded the evaluation work budget, which a database has no equivalent of.

## Plans

A plan is `{ kind, filter }`:

- `always`: every resource of the type (an owner, a root administrator, a grant without conditions);
- `never`: none (no grant applies, the tenant is inactive, the action is unknown);
- `conditional`: those that pass `filter`.

For a role like this one:

```json
{
  "version": 1,
  "statements": [
    {
      "effect": "allow",
      "actions": ["documents:read"],
      "resources": ["document/*"],
      "conditions": { "StringEquals": { "resource.ownerId": "${principal.id}" } }
    },
    { "effect": "allow", "actions": ["documents:*"], "resources": ["document/public-*"] },
    {
      "effect": "deny",
      "actions": ["documents:*"],
      "resources": ["document/*"],
      "conditions": { "StringEquals": { "resource.classification": "secret" } }
    }
  ]
}
```

the plan for `documents:read` on `document` is (as `describeFilter` prints it):

```text
not (classification = "secret") and (ownerId = "usr_alice" or id like "public-*")
```

The principal's variables are substituted, statements for other actions and types drop out, and conditions on the
person (`principal.mfa`, `principal.groups`, `request.time`, ...) are decided now. Resource patterns become conditions
on `id`: `document/public-*` is `id like "public-*"`. Conditions on `resource.{name}` become conditions on the field
`name`: `resource.tag.team` is the field `tag.team`. Relationship conditions become id lists: `ArrayContains` on
`resource.relations` turns into the ids of the resources the person holds the relation on (directly or through a
group), and on `resource.parentRelations` into the `parentType` / `parentId` pairs.

Everything a decision uses applies to the plan too: deny statements across every role, tenant boundaries, the
session's scope-down policy, an API key's scopes, access windows and just-in-time activations, and an agent's ceiling
and delegation scope. A "view as" session gets only what the administrator behind it could reach as well. A
delegation that holds the action back for the person's confirmation plans `never`: the resources confirmed a moment
ago are left to `authorize`.

## Filters

The filter is a small tree (`ResourceFilter` in `better-iam/core`):

| Kind                             | Passes when                                                                          |
| -------------------------------- | ------------------------------------------------------------------------------------ |
| `true`, `false`                  | always, never                                                                        |
| `and`, `or`, `not`               | the usual combinations                                                               |
| `exists`                         | the field is present                                                                 |
| `type`                           | the field holds a string, number, boolean, or IP address                             |
| `equals`                         | the field equals one of `values` (with the value's type; `ignoreCase` for strings)    |
| `compare`                        | a number field is `lt`, `le`, `gt` or `ge` a value                                   |
| `like`                           | a string field matches a glob (`*`, `?`; `\` escapes), optionally ignoring case       |
| `date`                           | an ISO 8601 timestamp field is `before` or `after` a moment                          |
| `ip`                             | an IP address field is inside a network                                              |
| `contains`                       | an array field contains a value                                                      |

A missing field (or SQL `NULL`) satisfies nothing but `not exists`, as a missing attribute satisfies no condition in
the engine. Every compiler keeps that rule under negation, so a deny statement on `classification` never hides rows
whose classification is empty.

## Compiling

| Function                     | Output                                        | Supports                                                     |
| ---------------------------- | --------------------------------------------- | ------------------------------------------------------------ |
| `filterMatches(filter, row)` | `boolean`                                     | everything, exactly                                          |
| `filterToSql(filter, opts)`  | `{ sql, params }` (PostgreSQL `$n`, SQLite `?`) | all but `ip` and `contains`                                  |
| `filterToPrisma(filter)`     | a Prisma `where`                              | globs that are exact, `prefix*`, `*suffix`, `*part*`; no dates or IPs |
| `filterToMongo(filter)`      | a MongoDB query                               | all but `date` and `ip`                                      |
| `describeFilter(filter)`     | a readable string                             | everything                                                   |

What a target cannot express refuses with `UNSUPPORTED_FILTER`; fall back to `filterMatches` over the candidate rows,
or to `authorize` per row.

`filterToSql` takes a `column(field)` function that maps each field to a trusted SQL expression of your schema (a
column, or a JSON path such as `data->>'owner'`), and returns undefined for fields your table does not have (the call
then refuses, rather than guessing). Values are always bound parameters. `offset` shifts PostgreSQL placeholders when
the filter sits inside a query that has parameters of its own. SQLite string matching uses `GLOB`, which is
case-sensitive like the engine; case-insensitive comparisons use `LOWER()`, which SQLite applies to ASCII letters
only. Columns should hold the types conditions compare: text for string conditions, numbers, booleans (SQLite `0`/`1`),
and ISO 8601 text for dates.

```ts
import { filterMatches, filterToMongo, filterToPrisma } from 'better-iam/core';

const documents = await prisma.document.findMany({
  where: { tenantId, ...filterToPrisma(plan.filter, { field: (name) => (name === 'ownerId' ? 'ownerId' : name) }) },
});
const cursor = mongo.collection('documents').find({
  tenantId,
  ...filterToMongo(plan.filter, { field: (name) => (name === 'id' ? '_id' : name) }),
});
const visible = candidates.filter((row) => filterMatches(plan.filter, { id: row.id, ...row.attributes }));
```

## Where the fields come from

The filter's fields are the attribute names the engine sees when it decides one resource. For application resources
those are the `attributes` your `resolveResource` returns; for managed resources (registered with IAM), the registry
record's attributes. Keep the plan's field names and your columns in step: a plan that names a field your
`column` mapper does not know refuses to compile.

## API

- `iam.planResources({ token | headers, tenantId, action, type })`: the caller's plan, in process.
- `plan({ action, type })` on the per-request helpers of the [Node framework integrations](node-frameworks.md)
  (`req.iam` in Express, `c.get('iam')` in Hono, `request.iam` in Fastify, `event.locals.iam` in SvelteKit, and React
  Router's `context`): the request's own plan, `never` when signed out.
- `filters.plan({ tenantId, action, type })` (`POST {basePath}/filters/plan`): the same over HTTP and the typed client.
  It needs only a session of the tenant and is not audited; your queries decide which rows come back, and
  `authorize` stays the check for one resource.
- `filters.planFor({ tenantId, identityId, action, type, assumeMfa? })`: an administrator's preview of another
  identity's plan without a session of theirs, like `policies.simulate`. Requires `iam:policies:simulate` on the
  identity; audited as that action.

Plans cover application actions on application and managed resource types; `iam:*` administration and IAM's internal
types refuse with `INVALID_INPUT`. The planner itself is `planResources` in `better-iam/core`, a pure function over
policy documents, if you want to plan policies of your own.
