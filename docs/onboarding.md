# Onboarding

Onboarding flows are checklists for newcomers, customized at every level of the tenant hierarchy:

- **Member onboarding** walks people who join a tenant through their first steps: read and confirm the rules, answer a
  few questions, finish tasks such as security training, accept terms of use, verify their email address, and enroll
  two-step verification or a passkey.
- **Tenant setup** walks the administrators of a new organization or project through what their parent asks of it: a
  second owner, a verified domain, an MFA policy, SSO, directory sync, a company profile, a business verification
  that the platform reviews.

Flows are defined at any level and inherited downward, like the tenant tree itself (`root → organization → project`
by default):

| Level                            | Defines                                                                                                   | Customizes what it inherits                                          |
| -------------------------------- | --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| **Platform** (the root tenant)   | Member onboarding for every organization and project, setup checklists for new organizations and projects | —                                                                    |
| **Organization**                 | Member onboarding for its own people, its projects' people, or both; setup checklists for its projects    | Switches off the platform's unlocked flows; its own welcome copy     |
| **Project** (or any leaf tenant) | Member onboarding for its own people                                                                      | Switches off the unlocked flows of the platform and its organization |

A person sees the flows of every level at once, platform first, in the **Get started** checklist. Policies can hold
access back until required flows are done (`principal.pendingOnboarding`), the same way they can for
[terms of use](policies.md#terms-of-use).

## Flows

```ts
// Platform level: every organization's and project's newcomers read the rules and fill in their profile.
const essentials = await iam.api.onboarding.createFlow(rootSession, {
  tenantId: rootTenantId,
  name: 'Platform essentials',
  audience: 'member',
  locked: true, // organizations and projects cannot switch it off
  steps: [
    {
      id: 'conduct',
      kind: 'acknowledge',
      title: 'Acceptable use',
      content: 'Use the service lawfully…',
    },
    {
      id: 'profile',
      kind: 'form',
      title: 'About you',
      fields: [
        { name: 'phone', label: 'Desk phone', type: 'text' },
        { name: 'timezone', label: 'Time zone', type: 'text', placeholder: 'Europe/Berlin' },
      ],
    },
    { id: 'mfa', kind: 'mfa', title: 'Set up two-step verification', optional: true },
  ],
});

// Organization level: Acme's own people pick their department, which fills principal.department.
await iam.api.onboarding.createFlow(ownerSession, {
  tenantId: acmeId,
  name: 'Acme profile',
  audience: 'member',
  steps: [
    {
      id: 'team',
      kind: 'form',
      title: 'Your team',
      fields: [
        {
          name: 'department',
          label: 'Department',
          type: 'select',
          options: ['Engineering', 'Sales'],
          required: true,
          attribute: 'department', // fills the attribute when it is empty
        },
      ],
    },
  ],
});

// Engineers then collect a laptop (verified by an administrator) and join a group.
await iam.api.onboarding.createFlow(ownerSession, {
  tenantId: acmeId,
  name: 'Engineering onboarding',
  audience: 'member',
  appliesTo: 'subtree', // Acme's people and the people of Acme's projects
  rule: { include: [{ StringEquals: { 'principal.department': 'Engineering' } }] },
  completionGroupIds: [engineersGroupId],
  steps: [{ id: 'laptop', kind: 'task', title: 'Collect your laptop', verification: 'admin' }],
});
```

A flow has:

| Field                | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `audience`           | `member` (people who join) or `tenant` (the setup of tenants below). Fixed once created.                                                                                                                                                                                                                                                                                                                                                |
| `appliesTo`          | Member flows: `tenant` (this tenant's own people), `descendants` (the people of tenants below it) or `subtree` (both). Defaults to `descendants` at the platform root and `tenant` elsewhere. Tenant flows always reach descendants. A tenant type without children only defines `tenant`.                                                                                                                                              |
| `tenantTypes`        | Only descendant tenants of these types (for example `['organization']` or `['project']`); all types when absent.                                                                                                                                                                                                                                                                                                                        |
| `rule`               | Member flows: only people this rule matches. It is the [access-package rule language](policies.md#automatic-assignment-birthright): `include` clauses (any matches) and optional `exclude` clauses over `principal.kind`, `principal.owner`, `identity.email`, `identity.emailDomain`, `identity.groups`, and declared attributes. Group tests name the defining tenant's groups, so flows that reach only descendants cannot use them. |
| `required`           | Required flows (the default) count toward `principal.pendingOnboarding` and the console banner until complete.                                                                                                                                                                                                                                                                                                                          |
| `locked`             | Inherited member flows a tenant below may not switch off.                                                                                                                                                                                                                                                                                                                                                                               |
| `includeExisting`    | Also ask people (or tenants) that existed before the flow took effect. Off by default: only newcomers are asked, so adding a flow never disrupts everyone at once.                                                                                                                                                                                                                                                                      |
| `enabled`            | Paused flows ask nobody. The flow takes effect (`effectiveFrom`) the first time it is enabled.                                                                                                                                                                                                                                                                                                                                          |
| `completionGroupIds` | Member flows that reach the defining tenant's own people: groups a person joins when they finish (at most 10).                                                                                                                                                                                                                                                                                                                          |
| `steps`              | 1-25 steps, each with a stable `id` (lowercase letters, digits, dashes). Changing the steps bumps `version`.                                                                                                                                                                                                                                                                                                                            |

A tenant defines at most 50 flows; names are unique per tenant (`CONFLICT`). `updateFlow` changes any field but the
audience; `deleteFlow` removes the flow with everyone's progress through it, in every tenant it reached.

### Steps

| Kind           | Audience | Completes when                                                                                                                              |
| -------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `form`         | both     | The answers are submitted: `fields` (1-20) of type `text`, `textarea`, `email`, `url`, `number`, `boolean`, `select`, or `date`.            |
| `acknowledge`  | both     | The reader confirms `content` (`acknowledged: true`).                                                                                       |
| `task`         | both     | Marked done (`verification: 'self'`, the default), or approved by an administrator after it is submitted (`verification: 'admin'`).         |
| `agreement`    | member   | The person has accepted the current version of the terms-of-use agreement named `agreement` in their own tenant. Skipped where none exists. |
| `verify-email` | member   | The person's email address is verified.                                                                                                     |
| `mfa`          | member   | The person has an authenticator app or a passkey.                                                                                           |
| `passkey`      | member   | The person has registered a passkey.                                                                                                        |
| `check`        | tenant   | The tenant's own state meets the check (below).                                                                                             |

Steps marked `optional: true` never hold a flow back. Steps that complete on their own (`agreement`, `verify-email`,
`mfa`, `passkey`, `check`) follow the live state, so removing the last passkey reopens a `passkey` step.

Setup `check` steps watch the tenant being set up: `verified-domain`, `members` and `owners` (at least `minimum`, 2 by
default, active people), `mfa-policy` (the tenant's auth policy requires MFA), `agreement` (terms of use published),
`slug` (a sign-in alias), `sso` (an enabled SAML connection), `directory-sync` (an inbound SCIM connection), and
`member-onboarding` (the tenant defines its own member onboarding).

### Answers that fill profile attributes

A form field with `attribute` fills that [declared identity attribute](policies.md#conditions) with the answer, so a
new member's department can drive their access (targeting rules, access-package rules, policies). Onboarding only
fills attributes that are **empty**: it never overwrites a value an administrator or directory sync set, and a person
cannot change their department by answering again. Values pass the same validation as `identities.update`, and
textarea fields cannot fill attributes (attribute values are single lines).

Answers fill attributes only for the **defining tenant's own people**. A tenant has no authority over the identities of
the tenants below it, whose own policies may grant access by those attributes, so a flow that reaches only descendants
cannot map fields at all (`INVALID_INPUT`), and a `subtree` flow records the answers of people in tenants below as
answers without writing their attributes. Mapping answers to attributes needs `iam:identities:update` when
the flow is saved; adding completion groups needs `iam:groups:update` on each group and the use of the grant
authorities behind the group's roles, like assigning an access package. Both are set from an ordinary session or API
key, never while impersonating.

## Customizing inherited onboarding

Each tenant has onboarding settings (`onboarding.setSettings`, replace semantics):

- `welcomeTitle`, `welcomeMessage`, `supportEmail`, `supportUrl`: the welcome screen above the checklist. For each
  value the nearest level that set it wins, so the platform sets defaults, an organization overrides the message, and a
  project overrides only the title.
- `disabledFlowIds`: inherited, unlocked member flows switched off for this tenant and every tenant below it. Locked
  flows are refused (`INVALID_INPUT`); when a flow is locked later, the switch is ignored and dropped the next time the
  settings are saved.

`onboarding.effective({ tenantId })` shows everything as the tenant sees it: the levels (`levels`, root first), every
member flow that reaches its people with where it comes from and whether it is switched off (`disabledBy`,
`canDisable`), the setup checklists it is asked to complete (`setupFlows`), its own flows (`ownFlows`), and the
settings with the level each value comes from. Inherited flows omit the defining tenant's completion groups and author.

## Working through onboarding

People work through their own flows without a permission, from an ordinary session of their tenant:

```ts
const mine = await iam.api.onboarding.mine(session, { tenantId });
// { tenant, welcome, flows: [{ name, source, required, steps: [{ id, kind, state, … }], done, total, complete }], pending, complete }

await iam.api.onboarding.submitStep(session, {
  tenantId,
  flowId,
  stepId: 'conduct',
  acknowledged: true,
});
await iam.api.onboarding.submitStep(session, {
  tenantId,
  flowId,
  stepId: 'profile',
  answers: { department: 'Engineering', phone: '555-0100' },
}); // → { flow, attributesFilled: ['department'] }
```

Step states are `pending`, `complete`, `submitted` (an administrator-verified task waiting for review), `rejected`
(sent back, with the reviewer's `note`), and `unavailable` (an agreement the tenant has not published). Service
accounts are never onboarded. Impersonating administrators see the checklist but cannot complete steps
(`IMPERSONATION_RESTRICTED`).

A flow is recorded as complete (`onboarding:complete`) the first time it is seen complete in its current version, and
its completion groups are applied then, in their own transaction: a separation-of-duties refusal keeps the completion
and records `completionError` on the progress, retried the next time the person's onboarding is read.

Tenant setup is completed by the tenant's administrators: `onboarding.setup({ tenantId })` (`iam:onboarding:read`)
lists the checklists with the state of every step, and `onboarding.submitSetupStep` (`iam:onboarding:manage`)
completes forms, acknowledgements, and tasks.

## Enforcing onboarding in policies

Every decision for a person in their own tenant can see `principal.onboarding` (a list: the names of the member flows
they have completed) and `principal.pendingOnboarding` (a number: how many required flows are still open). A deny statement holds access back until
onboarding is done:

```json
{
  "effect": "deny",
  "actions": ["documents:*"],
  "resources": ["*"],
  "conditions": { "NumericGreaterThan": { "principal.pendingOnboarding": 0 } }
}
```

The keys are read only when a condition names them, so tenants that do not use them pay nothing. Assumed roles see
none; session tokens keep their person's onboarding. Nothing in onboarding itself is gated by these keys: accepting
terms, verifying an email address, and enrolling MFA use their own APIs, so nobody is locked out of finishing.

## Progress, review, and reset

- `onboarding.progress({ tenantId, flowId })` (`iam:onboarding:read`): for member flows, the tenant's own people the
  flow applies to, with their progress, answers, and tasks awaiting review; a flow defined here that reaches tenants
  below adds per-tenant counts (`descendants`), never names. For setup flows defined here, every descendant tenant the
  flow applies to, with its answers.
- `onboarding.memberProgress({ tenantId, identityId })`: one person's flows and answers.
- `onboarding.verifyStep({ tenantId, flowId, subjectId, stepId, approve?, note? })` (`iam:onboarding:manage`):
  approves or sends back an administrator-verified task. For member flows the caller administers the person's tenant;
  for setup flows the caller administers the tenant that defines the flow and `subjectId` is the tenant being set up.
  People cannot verify their own onboarding.
- `onboarding.resetProgress({ tenantId, flowId, subjectId?, stepId? })`: the tenant that defines a flow may reset
  anyone it reaches (everyone when `subjectId` is omitted); a tenant the flow reaches may reset its own people.

Deleting a person removes their progress (it holds their answers). Purging a tenant removes its flows, settings, and
progress.

## Audit events

`onboarding:step` (a step completed or submitted; `flowId`, `flow`, `stepId`, `kind`, `awaitingVerification`,
`attributes` filled), `onboarding:complete` (`flowId`, `flow`, `version`, `subjectType`), `onboarding:verify` and
`onboarding:reject` (`flowId`, `flow`, `stepId`, `subjectType`, `note`), `onboarding:reset` (`flowId`, `flow`,
`reset`, `subjectId`, `stepId`), and `onboarding:groups` (completion groups applied; `flowId`, `flow`, `groupIds`).
Flow and settings changes are recorded as `iam:onboarding:manage` operations.

## Console

- **Administration → Onboarding** (root administrators): platform flows, the platform welcome screen, and progress
  reports, including every organization's setup answers with Approve / Send back for verified tasks.
- **Organization → Onboarding** (in an organization or a project): the levels, the welcome screen and switched-off
  inherited flows, inherited flows with progress, the tenant's own flows, and a builder with templates (new member
  essentials, security basics, organization setup, project setup).
- **Get started**: the signed-in person's checklist. A banner links to it while required steps are open.
- **Organization → Setup checklist** and a "Finish setting up" card on the overview: the tenant's own setup.
