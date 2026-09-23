# Feature flags

Feature flags turn product features on and off per tenant without a deploy. They work at two levels:

- **Platform flags** are defined on the root tenant by root administrators (or anyone the root tenant grants
  `iam:features:manage`). They reach every organization and project.
- **Tenant flags** are defined by an organization (or a project) for its own subtree: an organization can roll a
  feature out to some of its projects, or let each project choose.

Every flag is a boolean. Applications read flag values on the server (`iam.features`), in the browser
(`features.evaluate`, `useFeatureFlags`), and in policies (the `tenant.features` context key), so a feature can be
hidden in the UI and refused by authorization with the same switch.

## How a value is decided

A flag's value for a tenant comes from the first rule that applies:

1. **Kill switch.** `killSwitch: true` turns the flag off everywhere. Targets and overrides stay stored and apply
   again when the switch is lifted.
2. **The closest target or override.** Walking from the tenant up to (not including) the tenant that defines the
   flag, the first tenant with a value decides:
   - A **target** is a value the flag's managers pin for a tenant below them (`features.setTarget`), such as "on for
     Acme until the end of the trial". It applies to that tenant and everything below it.
   - An **override** is a tenant's own choice (`features.setOverride`) for a flag defined with
     `tenantOverridable: true`. On the same tenant, the tenant's override beats a target.
   - A **locked** target (`locked: true`) silences overrides at its tenant and below. The managers' own closer
     targets still apply.
   - Targets can lapse (`expiresAt`). A lapsed target is ignored.
3. **Rollout.** `rolloutPercentage` (0 to 100) turns an off-by-default flag on for a stable share of the branches
   directly below the defining tenant. For a platform flag, that means organizations, and an organization's projects
   land on the same side as the organization. Raising the percentage only adds tenants. The exported
   `rolloutBucket(key, tenantId)` (from `@better-iam/server`) shows where a tenant falls.
4. **Default.** `defaultValue`.

Keys belong to the tenant closest to the root: a tenant cannot define a key that an ancestor defines, and a platform
flag created later takes precedence over an organization flag with the same key. `features.list` reports the
organization's flag under `shadowed`. A tenant therefore can never switch a platform-gated feature on for itself.

Keys are lowercase letters and digits joined by `-`, `_`, or `.` (for example `new-billing` or `reports.v2`), up
to 64 characters. A tenant can define at most 200 flags.

## Managing flags

```ts
const root = { token: rootSessionToken };

// A platform flag that organizations may turn on for themselves.
await iam.api.features.create(root, {
  tenantId: rootTenantId,
  key: 'new-billing',
  description: 'The redesigned billing pages',
  tenantOverridable: true,
});

// A two-week trial of another flag for one organization, and a gradual rollout of a third.
await iam.api.features.setTarget(root, {
  tenantId: rootTenantId,
  key: 'fast-search',
  targetTenantId: acmeId,
  value: true,
  expiresAt: Date.now() + 14 * 86_400_000,
  note: 'Design partner trial',
});
await iam.api.features.update(root, {
  tenantId: rootTenantId,
  key: 'reports-v2',
  rolloutPercentage: 25,
});

// Acme's administrators opt in.
await iam.api.features.setOverride(acmeAdmin, {
  tenantId: acmeId,
  key: 'new-billing',
  value: true,
});

// Incident: off everywhere, now.
await iam.api.features.update(root, {
  tenantId: rootTenantId,
  key: 'fast-search',
  killSwitch: true,
});
```

| Method                                                                                     | Permission                                | What it does                                                                                                   |
| ------------------------------------------------------------------------------------------ | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `features.create({ tenantId, key, description?, defaultValue?, rolloutPercentage?, ... })` | `iam:features:manage`                     | Defines a flag in the tenant (a platform flag on the root tenant).                                             |
| `features.update({ tenantId, key, ...settings })`                                          | `iam:features:manage`                     | Changes settings. Omitted fields are kept, and `null` clears `description` or `rolloutPercentage`.             |
| `features.delete({ tenantId, key })`                                                       | `iam:features:manage`                     | Deletes the flag with all its targets and overrides. Code that asks for it gets `false`.                       |
| `features.setTarget({ tenantId, key, targetTenantId, value, locked?, expiresAt?, note? })` | `iam:features:manage` (defining tenant)   | Pins a value for a tenant below the defining one. `value: null` removes it.                                    |
| `features.listTargets({ tenantId, key })`                                                  | `iam:features:read` (defining tenant)     | Every target and override below the defining tenant, with `active` (counts right now).                         |
| `features.setOverride({ tenantId, key, value })`                                           | `iam:features:override` (the tenant)      | The tenant's own choice. `FEATURE_LOCKED` when the flag does not allow overrides or a locked target covers it. |
| `features.list({ tenantId })`                                                              | `iam:features:read`                       | The flags that reach the tenant, each with its evaluation, the tenant's override, and its target.              |
| `features.evaluate({ tenantId, keys? })`                                                   | a session of the tenant (or a root admin) | `{ tenantId, flags: { key: boolean } }` for applications. Not audited.                                         |

Each resource is `iam/features/{key}` (or `iam/features` for `list`), so a policy can delegate a single flag, for
example `iam:features:override` on `iam/features/new-*` for a product team. Changes are audited as `feature:create`,
`feature:update` (settings before and after), `feature:delete`, `feature:target`, and `feature:override`. Like all
audit events, they reach webhooks.

**Internal flags** (`internal: true`) are evaluated only by trusted server code and policies. They are hidden from
`features.evaluate` and from the `features.list` of tenants below the defining tenant (root administrators still see
them). Targets can reach them, but tenants cannot override them.

Notes on targets are visible only to the defining tenant's managers (`features.listTargets`). A tenant sees that a
target exists, its value, whether it is locked, and when it ends, but never the note.

## Reading flags in applications

On the server, with no credential (deployment code), internal flags included:

```ts
if (await iam.features.isEnabled(tenantId, 'new-billing')) showNewBilling();
const values = await iam.features.values(tenantId); // { 'new-billing': true, ... }
const [detail] = await iam.features.evaluate(tenantId, { keys: ['new-billing'] });
// detail: { key, value, reason: 'OVERRIDE', scope: 'platform', definedBy, decidedBy, locked, overridable }
```

From a browser or another service, with a session or API key of the tenant:

```ts
const { flags } = await client.features.evaluate({ tenantId });
```

In React:

```tsx
import { useFeatureFlag, useFeatureFlags } from 'better-iam/react';

function Billing({ tenantId }: { tenantId: string }) {
  const { value } = useFeatureFlag({ tenantId, key: 'new-billing' });
  return value ? <NewBilling /> : <Billing />;
}
function Toolbar({ tenantId }: { tenantId: string }) {
  const features = useFeatureFlags({ tenantId });
  return features.isEnabled('fast-search') ? <FastSearch /> : null;
}
```

Hooks return `false` while loading, when signed out, and for unknown keys. Hiding UI is not enforcement, so gate the
server side as well.

## Flags in policies

Decisions expose the keys of every flag that is on for the decision's tenant, internal flags included, as the list
`tenant.features`:

```json
{
  "effect": "allow",
  "actions": ["documents:export"],
  "resources": ["*"],
  "conditions": { "ArrayContains": { "tenant.features": "exports" } }
}
```

The server reads flags only for decisions whose documents name `tenant.features`, so policies that do not use flags
pay nothing. Applications cannot supply the key through `resolveContext` or plugins, because the server removes it.
`policies.test` fills it with the tenant's current flags, and policy lint knows it as a list.

## Console

- **Administration › Feature flags** (root): platform flags with their settings, kill switch, every target and
  organization choice, a form to target an organization or project (optionally locked or lapsing), and new flags.
- **Organization › Features**: the platform's flags as they apply to the organization, with **Turn on**,
  **Turn off**, and **Use default** buttons where the platform allows a choice. It also lists the organization's own
  flags, with per-project targets and settings.
