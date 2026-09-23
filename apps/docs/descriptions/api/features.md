# features

Feature flags turn product features on and off per tenant without a deploy. Flags the root tenant defines are
platform flags and reach every organization and project; flags an organization or project defines reach only its own
subtree. A key belongs to the tenant closest to the root, so a tenant can never shadow a platform flag. Every flag is
a boolean, read by applications through `evaluate`, by server code through `iam.features` (`evaluate`, `values`,
`isEnabled`, no credential), and by policies through the `tenant.features` condition key. The repository guide is
`docs/feature-flags.md`.

## How a value is decided

For a given tenant, the first rule that applies decides:

1. The **kill switch** (`killSwitch: true`): off everywhere.
2. The **closest target or override** on the way from the tenant up to (not including) the defining tenant. A target
   is a value the flag's managers pin for a tenant below them (`setTarget`); an override is a tenant's own choice for
   a `tenantOverridable` flag (`setOverride`). On the same tenant the override wins; a `locked` target silences
   overrides at its tenant and below. Targets can lapse (`expiresAt`).
3. The **rollout** (`rolloutPercentage`, 0 to 100): a stable share of the branches directly below the defining tenant
   gets `true`, so an organization and its projects land on the same side. Raising it only adds tenants.
4. The **default** (`defaultValue`).

Resources are `iam/features/{key}` (and `iam/features` for `list`), so a policy can delegate one flag or a family,
such as `iam:features:override` on `iam/features/beta-*`.

## create

Defines a flag in the tenant: a platform flag on the root tenant, a flag for the tenant's subtree elsewhere.

- **Permission:** `iam:features:manage` on `iam/features/{key}`.
- **Audited as:** `feature:create`, with the settings.
- **Errors:** `CONFLICT` (409) when the tenant or one of its ancestors already defines the key; `LIMIT_EXCEEDED` (409)
  past 200 flags in the tenant; `INVALID_INPUT` for a malformed key, an unknown field, `rolloutPercentage` with
  `defaultValue: true`, or an `internal` flag that is also `tenantOverridable`; `INVALID_TRANSITION` in a deleted
  tenant.

Keys are lowercase letters and digits joined by `-`, `_`, or `.`, starting with a letter, at most 64 characters.
Settings default to off, not overridable, no kill switch, not internal. `internal` flags are evaluated only by server
code and policies and are hidden from tenants below the defining one.

```ts
await iam.api.features.create(rootCredential, {
  tenantId: rootTenantId,
  key: 'new-billing',
  description: 'The redesigned billing pages',
  tenantOverridable: true,
});
```

## delete

Deletes a flag together with every target and override set for it.

- **Permission:** `iam:features:manage` on `iam/features/{key}`.
- **Audited as:** `feature:delete`, with `removedTargets`.
- **Errors:** `NOT_FOUND` when the tenant does not define the key.

Code that still asks for the key gets `false` (reason `UNKNOWN`). The result is `{ success: true, removedTargets }`.

## evaluate

Returns `{ tenantId, flags: { key: boolean } }` for the flags that reach the tenant, for applications deciding what to
show.

- **Permission:** None beyond a session (user, API key, role, or session token) of the tenant; root administrators may
  evaluate any tenant.
- **Audited as:** not audited.
- **Errors:** `ACCESS_DENIED` (403) for a session of another tenant; `INVALID_INPUT` for a malformed key or more than
  100 keys.

Internal flags of ancestors are left out. `keys` limits the answer to those flags, and a requested key that no flag
defines comes back `false`. The React hooks `useFeatureFlags` and `useFeatureFlag` call it.

```ts
const { flags } = await client.features.evaluate({ tenantId });
if (flags['new-billing']) showNewBilling();
```

## list

The flags that reach the tenant, sorted by key, each with its value for the tenant and why.

- **Permission:** `iam:features:read` on `iam/features`.
- **Audited as:** `iam:features:read`.

Each entry has `evaluation` (`value`, `reason` of `KILL_SWITCH`, `TARGET`, `OVERRIDE`, `ROLLOUT`, or `DEFAULT`,
`decidedBy`, `expiresAt`, `locked`, and `overridable`), the tenant's own `override`, and the `target` pinned for it.
Flags the tenant defines also carry `definition` with their settings. Ancestors' internal flags are left out, except
for root administrators, who see every flag with its definition. `shadowed` lists flags this tenant defines whose key
an ancestor also defines, so the ancestor's flag applies. Rename or delete them.

## listTargets

Every target and override below the defining tenant for one flag, newest first.

- **Permission:** `iam:features:read` on `iam/features/{key}`, in the defining tenant.
- **Audited as:** `iam:features:read`.
- **Errors:** `NOT_FOUND` when the tenant does not define the key.

Each entry names the tenant (`tenantName`, `tenantStatus`), the `source` (`target` or `override`), the value,
`locked`, `expiresAt`, the `note`, and `active`: false once a target has lapsed or an override is no longer allowed.
Only the defining tenant's managers see notes.

## setOverride

Records a tenant's own choice for a flag an ancestor defines with `tenantOverridable: true`.

- **Permission:** `iam:features:override` on `iam/features/{key}`, in the tenant.
- **Audited as:** `feature:override`, with the value (`null` when withdrawn).
- **Errors:** `FEATURE_LOCKED` (409) when the flag does not allow overrides or a locked target covers the tenant;
  `NOT_FOUND` for a key no flag defines or an ancestor's internal flag; `INVALID_INPUT` when the tenant defines the flag
  itself (change it with `update`).

The choice applies to the tenant and its descendants unless something closer decides. `value: null` withdraws it,
which is always allowed. The result is the tenant's new evaluation.

## setTarget

Pins a flag's value for a tenant below the defining tenant (`tenantId`), and for that tenant's descendants.

- **Permission:** `iam:features:manage` on `iam/features/{key}`, in the defining tenant.
- **Audited as:** `feature:target`, recorded in the defining tenant with `targetTenantId`, `value`, `locked`, and
  `expiresAt`.
- **Errors:** `INVALID_INPUT` when `targetTenantId` is not below the defining tenant (use `defaultValue` for the tenant
  itself) or `expiresAt` is not in the next ten years; `NOT_FOUND` when the tenant does not define the key.

`locked: true` keeps the tenant and everything below it from overriding. `expiresAt` makes the target lapse by
itself, for a trial or a temporary block. `note` is visible only to the defining tenant's managers. `value: null`
removes the target.

```ts
await iam.api.features.setTarget(rootCredential, {
  tenantId: rootTenantId,
  key: 'fast-search',
  targetTenantId: acmeId,
  value: true,
  expiresAt: Date.now() + 14 * 86_400_000,
  note: 'Design partner trial',
});
```

## update

Changes a flag's settings. Fields left out keep their value.

- **Permission:** `iam:features:manage` on `iam/features/{key}`.
- **Audited as:** `feature:update`, with the settings `before` and `after`.
- **Errors:** `NOT_FOUND` when the tenant does not define the key; `INVALID_INPUT` as for `create`.

`null` clears `description` or `rolloutPercentage`. Turning `killSwitch` on switches the flag off for every tenant at
once, and turning it off restores the stored targets, overrides, and rollout. Turning `tenantOverridable` off keeps
existing overrides but ignores them.
