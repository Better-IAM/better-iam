# resources

This group registers the resources your product protects, so authorization can decide about them without calling
back into your application. A registration records a resource's typed attributes, its owner, and its parent,
and policies read them as `resource.*` context keys. Registered resources can also be listed by what the caller may
do with them (`iam.listAccessible`), which is what makes filtered list pages possible.

## Managed and application-owned resources

Every resource type is one of two kinds (see [managed types](/docs/guides/authorization/catalog#managed-types)):

- **Application-owned** types are resolved by your application at decision time through the `resolveResource` option.
  Your database stays the source of truth and nothing is registered here.
- **Managed** types (declared with `managed: true`, and every [tenant-defined type](/docs/reference/api/resource-types))
  are registered through this group. Authorization reads the registration, so no callback is involved, and
  `listAccessible` can enumerate them.

This group only accepts managed types; an application-owned or unknown type fails with `INVALID_RESOURCE_TYPE`. A
registration is addressed by `type` and `id` (your identifier, at most 128 characters). The returned record keeps your
identifier in `resourceId`; its `id` field is an internal record id.

During evaluation a registered resource exposes its attributes as `resource.{name}`, plus `resource.ownerId`,
`resource.parentId`, and `resource.parentType` when set, and the caller's
[relations](/docs/reference/api/relationships) on it and on its parent. Administrative calls on `iam/{type}/{id}` see
the same keys, so a policy can let owners manage their own resources:

```ts
{
  effect: 'allow',
  actions: ['iam:resources:update', 'iam:resources:delete'],
  resources: ['iam/project/*'],
  conditions: { StringEquals: { 'resource.ownerId': '${principal.id}' } },
}
```

Attribute values must match the type's declared schema: only declared names, with the declared type (`string`,
`number`, or `boolean`); strings are at most 2048 characters with no control characters.

## delete

Removes a registered resource and every relationship tuple on it.

- **Permission:** `iam:resources:delete` on `iam/{type}/{id}`.
- **Audited as:** `iam:resources:delete`, on `{type}/{id}`.
- **Errors:** `NOT_FOUND` when the resource is not registered; `RESOURCE_IN_USE` when registered child resources
  still point at it; `INVARIANT_VIOLATION` when an enforced
  [access invariant](/docs/guides/governance/change-safety) would newly fail.

Delete children first: a parent cannot be removed while resources registered under it exist. Once deleted, any
decision about the resource sees no attributes, owner, or relations.

## get

Returns the registration of one resource.

- **Permission:** `iam:resources:read` on `iam/{type}/{id}`.
- **Audited as:** `iam:resources:read`, on `{type}/{id}`.
- **Errors:** `NOT_FOUND` when the resource is not registered.

## list

Lists registered resources, optionally of one type, under one parent, or owned by one identity.

- **Permission:** `iam:resources:read` on `iam/{type}/*` when `type` is given, otherwise on `iam/*`.
- **Audited as:** `iam:resources:read`.
- **Errors:** `INVALID_INPUT` when `limit` is outside 1 to 1000.

Results are sorted by `type/id`, so pages are stable and meaningful; `limit` defaults to 100, with `offset` for the
next page. `parentId` is the parent's own identifier. This is an administrative listing of what exists. To list what a
person may act on, use [`listAccessible`](/docs/reference/api#listaccessible).

## register

Registers a managed resource with its attributes, owner, and parent.

- **Permission:** `iam:resources:create` on `iam/{type}/{id}`.
- **Audited as:** `iam:resources:create`, on `{type}/{id}`.
- **Errors:** `INVALID_RESOURCE_TYPE` when the type is unknown or application-owned; `CONFLICT` when the resource is
  already registered; `INVALID_INPUT` for undeclared or wrongly typed attributes, a missing `parentId` on a type that
  declares a parent, or a `parentId` on a type that does not; `NOT_FOUND` when the parent is not registered or
  `ownerId` is not an identity of the tenant (or was deleted); `LIMIT_EXCEEDED` at the tenant's resource limit.

Because the permission is checked on the resource's own address, policies can limit who registers what, for example
`iam/project/*` for project administrators. Register a resource when your product creates it, in the same request, so
access rules apply from the first moment. The parent cannot be changed later.

```ts
await iam.api.resources.register(credential, {
  tenantId,
  type: 'task',
  id: 'task_812',
  parentId: 'proj_apollo', // a registered `project`, because `task` declares `parent: 'project'`
  ownerId: identityId,
  attributes: { priority: 2 }, // the type declares `priority: 'number'`
});
```

## registerMany

Registers up to 100 managed resources in one transaction, either all of them or none.

- **Permission:** `iam:resources:create` on `iam/{type}/{id}` for every item.
- **Audited as:** `iam:resources:create`, once per item.
- **Errors:** `INVALID_INPUT` for an empty list or more than 100 items; `ACCESS_DENIED` naming the first item the
  caller may not register (only that denial is recorded and nothing is written); `LIMIT_EXCEEDED` when the whole batch
  does not fit the tenant's limit; any error [`register`](#register) raises for one item rejects the batch.

Every item is authorized before anything is written. Use it to import existing data or to register a parent and its
children together (list the parent first).

## update

Replaces a registered resource's attributes, or changes or clears its owner.

- **Permission:** `iam:resources:update` on `iam/{type}/{id}`.
- **Audited as:** `iam:resources:update`, on `{type}/{id}`.
- **Errors:** `NOT_FOUND` when the resource is not registered or the new owner is not in this tenant;
  `INVALID_INPUT` for undeclared or wrongly typed attributes; `INVALID_RESOURCE_TYPE`; `INVARIANT_VIOLATION` when an
  enforced access invariant would newly fail.

`attributes` replaces the whole attribute set, so send every attribute you want to keep. `ownerId: null` removes the
owner. Keep registrations current when the underlying record changes: a condition such as
`Bool: { 'resource.archived': false }` sees only what was last registered. Offboarding a person with
[`identities.offboard`](/docs/reference/api/identities#offboard) can transfer the resources they own to a successor.
