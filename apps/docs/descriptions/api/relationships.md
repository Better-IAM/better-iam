# relationships

Relationships record that a person or group stands in a named relation, such as `owner` or `viewer`, to one resource.
_Alice is an `owner` of `folder/plans`_; _the design group are `viewer`s of `folder/plans`_. They express per-resource
sharing and ownership (relationship-based access control) without writing resource ids into policies: one role says
"viewers may read", and sharing a folder is a single tuple instead of a policy edit. The
[relationships guide](/docs/guides/authorization/relationships) shows the full pattern.

## How policies read relations

A tuple is `{type}/{id}#{relation}@{subjectType}:{subjectId}`. The relation must be declared on the resource type
(`relations` in `permissions.resourceTypes`, or on a
[tenant-defined type](/docs/reference/api/resource-types#register)). The subject is an identity or a group; a
group's tuples apply to its current members.

When a decision is made, the caller's live relations on the evaluated resource appear as `resource.relations` (a
sorted array of names) and those on its registered parent as `resource.parentRelations`. Test them with
`ArrayContains`:

```ts
{ effect: 'allow', actions: ['files:read'], resources: ['file/*'],
  conditions: { ArrayContains: { 'resource.parentRelations': ['viewer', 'editor', 'owner'] } } }
```

Administrative calls on `iam/{type}/{id}` see the relations on the named resource too, which is how an owner can share
their own folder without a tenant-wide administrator role: grant `iam:relationships:create` on `iam/folder/*` under the
condition `ArrayContains: { 'resource.relations': ['owner'] }`. Role sessions hold no relations. Expired tuples stop
counting at once and are removed later by `iam.sweepExpired()`. Tuples are also removed with their identity, their
group, or their managed resource. [`listAccessible`](/docs/reference/api#listaccessible) takes relations into account.

## create

Gives an identity or group a declared relation on one resource, optionally until a given time.

- **Permission:** `iam:relationships:create` on `iam/{type}/{id}`.
- **Audited as:** `iam:relationships:create`, on `{type}/{id}`.
- **Errors:** `INVALID_RESOURCE_TYPE` when the type is not declared; `INVALID_INPUT` when the relation is not declared
  for the type, the subject type is not `identity` or `group`, or `expiresAt` is not in the future (at most ten years
  out); `NOT_FOUND` when a managed resource is not registered, the identity is not in this tenant or was deleted, or
  the group is not in this tenant; `INVARIANT_VIOLATION` when an enforced
  [access invariant](/docs/guides/governance/change-safety) would newly fail.

Resources of managed types must be registered first; resources of application-owned types are accepted as named.
Creating a tuple that already exists replaces it instead of failing: its `expiresAt` becomes the one you pass (none
makes it permanent) and the caller is recorded as `createdBy`. Use `expiresAt` for time-boxed sharing, such as giving
an auditor `viewer` on a folder for a week.

```ts
await iam.api.relationships.create(credential, {
  tenantId,
  type: 'folder',
  id: 'plans',
  relation: 'viewer',
  subjectType: 'group',
  subjectId: designGroupId,
  expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
});
```

## delete

Removes one relationship tuple, ending the access it gave.

- **Permission:** `iam:relationships:delete` on the tuple's resource, `iam/{type}/{id}`.
- **Audited as:** `iam:relationships:delete`, on `{type}/{id}`.
- **Errors:** `NOT_FOUND` when the tuple is not in this tenant; `INVARIANT_VIOLATION` when an enforced access
  invariant would newly fail.

Pass the tuple's `id`, as returned by [`create`](#create) or [`list`](#list). The change applies to the next
decision.

## list

Lists relationship tuples of one resource, one subject, one type, or the whole tenant, newest first.

- **Permission:** `iam:relationships:read` on `iam/{type}/{id}` when `type` and `id` are given, on `iam/{type}/*`
  when only `type` is, otherwise on `iam/*`.
- **Audited as:** `iam:relationships:read`.
- **Errors:** `INVALID_INPUT` for a subject type other than `identity` or `group`.

Filter by `type`, `id`, `relation`, `subjectType`, and `subjectId` in any combination: "who can see this folder" is
`{ type, id }`, and "what has been shared with this group" is `{ subjectType: 'group', subjectId }`. Expired tuples
are left out unless `includeExpired` is `true`. Because the permission is checked on the resource, an owner allowed to
read relationships on their own folder can review who it is shared with.
