# onboarding

Onboarding flows are checklists for newcomers, customized at every level of the tenant tree. `member` flows walk
people who join a tenant through their first steps (forms, acknowledgements, tasks, accepting terms of use, verifying
their email address, enrolling MFA or a passkey); `tenant` flows are setup checklists for the organizations or projects
below the defining tenant, with checks that follow the tenant's real state (a verified domain, enough owners and
members, an MFA policy, SSO, directory sync). Flows defined at the platform root reach every tenant below;
organizations and projects add their own, switch off unlocked inherited flows, and override the welcome screen. The
repository guide is `docs/onboarding.md`.

## Levels and inheritance

A flow's `appliesTo` decides whom it reaches: `tenant` (the defining tenant's own people), `descendants` (the people
of the tenants below it) or `subtree` (both); `tenantTypes` narrows descendants to some tenant types. Tenant flows
always reach descendants. A person sees the flows of every level at once, platform first. A tenant switches off an
inherited member flow for itself and everything below it with `setSettings({ disabledFlowIds })`, unless the flow is
`locked`. Welcome values (`welcomeTitle`, `welcomeMessage`, `supportEmail`, `supportUrl`) come from the nearest level
that set them.

Flows ask only people (or tenants) created after they took effect, unless `includeExisting` is set; member flows can
also target people with a `rule` in the access-package rule language. Policies see `principal.onboarding` (completed
flow names) and `principal.pendingOnboarding` (required flows still open), read only when a condition names them:

```json
{
  "effect": "deny",
  "actions": ["documents:*"],
  "resources": ["*"],
  "conditions": { "NumericGreaterThan": { "principal.pendingOnboarding": 0 } }
}
```

## createFlow

Creates a flow at this tenant's level.

- **Permission:** `iam:onboarding:manage` on the tenant. Form fields that fill identity attributes (`attribute`) also
  need `iam:identities:update`; `completionGroupIds` need `iam:groups:update` on each group and the use of the grant
  authorities behind the group's bindings. Both are refused from role sessions, session tokens, and impersonation.
- **Audited as:** `iam:onboarding:manage`.
- **Errors:** `CONFLICT` (409) for a name the tenant already uses; `LIMIT_EXCEEDED` (409) past 50 flows;
  `INVALID_INPUT` for an unknown field, a step kind the audience does not allow, duplicate step IDs, an undeclared or
  mistyped attribute, a textarea field mapped to an attribute, attribute mappings on a flow that reaches only tenants
  below, `tenantTypes` that cannot exist below the tenant, `descendants` on a tenant type without
  children, completion groups on a flow that reaches only descendants, or a rule that tests `identity.groups` on such a
  flow; `NOT_FOUND` for an unknown completion group; `ACCESS_DENIED` when the attribute or group permissions are
  missing.

Steps (1-25) have a stable `id` (lowercase letters, digits, dashes) and a `kind`: `form` (1-20 `fields`), `acknowledge`
(`content`), `task` (`url`, `verification: 'self' | 'admin'`), and for member flows `agreement` (by name),
`verify-email`, `mfa`, `passkey`; for tenant flows `check` (`verified-domain`, `members`, `owners`, `mfa-policy`,
`agreement`, `slug`, `sso`, `directory-sync`, `member-onboarding`, with `minimum` for members and owners). `appliesTo`
defaults to `descendants` at the root and `tenant` elsewhere.

```ts
await iam.api.onboarding.createFlow(rootCredential, {
  tenantId: rootTenantId,
  name: 'Platform essentials',
  audience: 'member',
  locked: true,
  steps: [
    { id: 'conduct', kind: 'acknowledge', title: 'Acceptable use', content: 'Use the service lawfully.' },
    { id: 'mfa', kind: 'mfa', title: 'Set up two-step verification' },
  ],
});
```

## deleteFlow

Deletes a flow with every progress record of it, in every tenant it reached, and removes it from tenants'
`disabledFlowIds`.

- **Permission:** `iam:onboarding:manage` on the flow.
- **Audited as:** `iam:onboarding:manage`.
- **Errors:** `NOT_FOUND` when this tenant does not define the flow.

Returns `{ deleted: true, progressRemoved }`.

## effective

Everything onboarding looks like from this tenant, for administration pages.

- **Permission:** `iam:onboarding:read` on the tenant.
- **Audited as:** `iam:onboarding:read`.

Returns the `levels` (root first), `memberFlows` reaching the tenant's people (own and inherited, each with `source`,
`inherited`, `disabledBy`, and `canDisable`), the `setupFlows` the tenant's administrators complete, its `ownFlows`,
the `descendantTypes` a flow may target, the declared `identityAttributes`, and `settings` (`own` and `resolved`, with
the level each value came from). Inherited flows omit the defining tenant's completion groups and author.

## getFlow

Returns one flow this tenant defines.

- **Permission:** `iam:onboarding:read` on the flow.
- **Audited as:** `iam:onboarding:read`.
- **Errors:** `NOT_FOUND` when this tenant does not define the flow.

## listFlows

Lists the flows this tenant defines, oldest first, optionally for one `audience`.

- **Permission:** `iam:onboarding:read` on the tenant.
- **Audited as:** `iam:onboarding:read`.

## memberProgress

One person's member flows in this tenant, with the state of every step and their answers, and `pending` (required
flows still open).

- **Permission:** `iam:onboarding:read` on the identity.
- **Audited as:** `iam:onboarding:read`.
- **Errors:** `NOT_FOUND` for an identity outside the tenant or deleted.

## mine

The caller's own onboarding: the welcome screen and their member flows, with step states and their own answers.

- **Permission:** None beyond an ordinary session (or API key) of the tenant.
- **Audited as:** `onboarding:complete` for each flow seen complete for the first time in its current version.
- **Errors:** `ACCESS_DENIED` from a role session, a session token, or another tenant's session.

Returns `{ tenant, welcome, flows, pending, complete }`. Each flow carries `source` (the level that defines it),
`required`, `steps` (`state`: `pending`, `complete`, `submitted`, `rejected` with the reviewer's `note`, or
`unavailable`), `done`, and `total`. Completion groups of newly finished flows are applied after the read, in their own
transaction; a refusal (such as a separation-of-duties rule) is kept as the progress record's `completionError` and
retried on the next read. Impersonating administrators see the checklist, but nothing is recorded. Service accounts
have no flows.

## progress

Progress through one flow as this tenant sees it.

- **Permission:** `iam:onboarding:read` on the flow.
- **Audited as:** `iam:onboarding:read`.
- **Errors:** `NOT_FOUND` when the flow neither belongs to nor reaches this tenant (setup flows report only at the
  tenant that defines them).

For member flows, `members` lists this tenant's people the flow applies to, with `done`, `total`, `complete`,
`awaiting` (tasks waiting for review), and `answers` by step. A flow defined here that reaches tenants below adds
`descendants`: per tenant, how many people it applies to and how many finished, never names. For setup flows,
`tenants` lists every descendant tenant the flow applies to, with its answers. `summary` counts subjects and completions;
`truncated` is set past 1000 descendant tenants.

## resetProgress

Clears progress through a flow, or one step of it (`stepId`), so people or tenants go through it again.

- **Permission:** `iam:onboarding:manage` on the flow. The tenant that defines the flow may reset anyone it reaches
  (everyone when `subjectId` is omitted); a tenant a member flow reaches may reset its own people.
- **Audited as:** `onboarding:reset`, with `reset` (the number of progress records) and the `subjectId` / `stepId`.
- **Errors:** `NOT_FOUND` for a flow that does not reach the tenant or an unknown step.

## setSettings

Replaces this tenant's onboarding settings: `welcomeTitle`, `welcomeMessage`, `supportEmail`, `supportUrl` (empty or
`null` falls back to the level above), and `disabledFlowIds`, the inherited member flows switched off for this tenant
and every tenant below it.

- **Permission:** `iam:onboarding:manage` on the tenant.
- **Audited as:** `iam:onboarding:manage`.
- **Errors:** `INVALID_INPUT` for a flow that is not an inherited member flow of the tenant, a locked flow, a malformed
  email or URL, or an unknown field.

A switch kept from before whose flow no longer reaches the tenant (deleted, retargeted, or locked since) is dropped
quietly, so re-saving never fails on someone else's change.

## setup

This tenant's own setup checklists (the tenant flows defined above it), with the state of every step and the answers.

- **Permission:** `iam:onboarding:read` on the tenant.
- **Audited as:** `iam:onboarding:read`, and `onboarding:complete` for a checklist seen complete for the first time.

Returns the same shape as `mine`. Check steps carry a `detail` such as `1 of 2 owners`.

## submitSetupStep

Completes a `form`, `acknowledge`, or `task` step of this tenant's setup.

- **Permission:** `iam:onboarding:manage` on the flow.
- **Audited as:** `onboarding:step`, and `onboarding:complete` when the checklist is done.
- **Errors:** `INVALID_INPUT` for a check step (they follow the tenant's state), missing or invalid answers, or an
  acknowledgement without `acknowledged: true`; `IMPERSONATION_RESTRICTED` while impersonating; `NOT_FOUND` for a flow
  that does not apply to the tenant or an unknown step.

## submitStep

Completes one step of the caller's own member flow: `answers` for a form, `acknowledged: true` for an acknowledgement,
nothing for a task (an `admin`-verified task is submitted for review).

- **Permission:** None beyond an ordinary session of the tenant.
- **Audited as:** `onboarding:step` (with the attributes the answers filled), and `onboarding:complete` when the flow is
  done.
- **Errors:** `INVALID_INPUT` for a step that completes on its own, a missing required answer, an answer of the wrong
  type or outside a select's choices, or an unknown answer key; `IMPERSONATION_RESTRICTED` while impersonating;
  `NOT_FOUND` for a flow that does not apply to the caller or an unknown step.

Answers mapped to identity attributes fill only empty attributes, and only when the caller's own tenant defines the
flow (an inherited flow records answers but never writes the tenant's identities); values an administrator or
directory sync set are kept. Returns `{ flow, attributesFilled }`.

```ts
await iam.api.onboarding.submitStep(credential, {
  tenantId,
  flowId,
  stepId: 'profile',
  answers: { department: 'Engineering' },
});
```

## updateFlow

Changes any field of a flow but its audience. Changing the steps bumps `version`: finished steps stay finished
(progress is kept per step ID) and a new required step reopens the flow for everyone it applies to.

- **Permission:** `iam:onboarding:manage` on the flow, plus the attribute and group permissions of `createFlow` for newly
  mapped attributes and newly added completion groups.
- **Audited as:** `iam:onboarding:manage`.
- **Errors:** as `createFlow`, and `NOT_FOUND` when this tenant does not define the flow.

`null` clears `description`, `tenantTypes`, `rule`, and `completionGroupIds`. Pausing (`enabled: false`) asks nobody;
the flow's `effectiveFrom` is set the first time it is enabled.

## verifyStep

Approves (the default) or sends back (`approve: false`, with an optional `note`) an administrator-verified task.

- **Permission:** `iam:onboarding:manage`. For member flows the caller administers the person's tenant (`tenantId`)
  and `subjectId` is the person; for setup flows the caller administers the tenant that defines the flow and
  `subjectId` is the tenant being set up.
- **Audited as:** `onboarding:verify` or `onboarding:reject`.
- **Errors:** `INVALID_INPUT` for a step that is not an administrator-verified task, or when people verify their own
  onboarding; `IMPERSONATION_RESTRICTED` while impersonating; `NOT_FOUND` when the flow does not apply to the subject.

Approving the last open step records the flow as complete; completion groups are applied the next time the person
reads their onboarding.
