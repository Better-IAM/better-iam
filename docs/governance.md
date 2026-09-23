# Access governance

Roles and bindings say who _may_ do what. Governance is the loop that keeps that true over time: find access nobody uses, simplify how it is granted, check a change before making it, hold lines no change may cross, get people to agree to the rules, and help them get what they need without an administrator. This guide walks the loop with the APIs that implement it; [policies](policies.md) has the reference for each call.

| Question                                        | Feature                       | API                                                    |
| ----------------------------------------------- | ----------------------------- | ------------------------------------------------------ |
| Which grants are redundant or could be simpler? | Role mining                   | `roleMining.suggest` / `apply`                         |
| Who holds access unlike their peers?            | Peer outliers                 | `roleMining.outliers`                                  |
| Which access is actually used?                  | Access usage and right-sizing | `accessUsage` option, `roleMining.usage` / `rightSize` |
| Should this person keep this role?              | Review recommendations        | `roleMining.reviewRecommendations`                     |
| What happens if I edit this role?               | Change impact preview         | `impact.preview`                                       |
| What must never (or always) be possible?        | Access invariants             | `invariants.*`, `iam.checkInvariants()`                |
| Have people accepted the rules?                 | Terms of use                  | `agreements.*`, `principal.pendingAgreements`          |
| How can I get access myself?                    | Self-service access paths     | `accessPaths.find`, `useAccessPaths`                   |

Every read above needs `iam:analysis:read` (role mining, usage, recommendations), `iam:policies:simulate` (impact), `iam:invariants:read`, or `iam:agreements:read`; the console's Organization section has a page for each.

## 1. Measure: record what people use

Turn on usage tracking once and let it run for a review period:

```ts
const iam = betterIam({ /* ... */ accessUsage: true });
// on shutdown
await iam.flushAccessUsage();
```

Every allowed authorization check and provisioning operation is counted in memory per person and action and written in batches, so the request path never waits on storage. After a full window, `roleMining.rightSize({ tenantId, unusedDays: 90 })` lists bindings whose holders used none (`unused`) or only some (`partial`) of the role's actions, and, per role, the actions nobody used, which are candidates for a narrower role. Until usage covers the window, `complete` is false and "unused" only means "not since tracking started".

## 2. Simplify: mine the roles you have

`roleMining.suggest({ tenantId })` reads who holds what and proposes:

- **redundant-binding**: direct bindings a permanent group membership already covers (same role, same authority, at least as broad). Removing them changes nothing today.
- **group-binding**: a role every member of a group holds directly; bind it to the group once so joiners get it and leavers lose it.
- **duplicate-roles**: roles whose statements are identical.
- **bundle**: role combinations many people hold together; grant them as one [access package](privileged-access.md) (optionally assigned automatically by attribute).

`roleMining.apply({ tenantId, suggestionId })` carries out the first two in one transaction, under the authority the original bindings used and with the caller's own binding rights; bundles become packages with `packages.create`. `roleMining.outliers({ tenantId, peerBy: 'attribute:department' })` compares each person with peers who share a manager or an attribute value and lists roles few peers hold (access that outlived a move) and roles most peers hold that the person lacks (what a joiner still needs).

## 3. Review: certify with evidence

Access-certification campaigns ask reviewers to keep or revoke each binding. `roleMining.reviewRecommendations({ tenantId, campaignId })` gives each item a suggestion and a reason: revoke when the account is disabled or expired, or when the role was not used in the window (recorded usage once it covers the window, the last sign-in before that); keep when it was. The console shows the suggestion beside each open item; reviewers still decide.

## 4. Change safely: preview, then guard

Before editing a role or policy, preview it:

```ts
const preview = await iam.api.impact.preview(credential, {
  tenantId,
  change: { role: { roleId, permissions: ['payments:read', 'payments:approve'] } },
  resources: [{ type: 'ledger', id: 'main' }],
});
// preview.identities: who gains and loses which actions on each resource
// preview.invariants.broken: guardrails the change would break
```

The change is applied with the real validation and permissions inside a transaction that is always rolled back, and every holder (through groups and role inheritance) is evaluated before and after, so conditions, ceilings, boundaries, windows, and eligibility all count.

Then write down the lines that must hold regardless of roles:

```ts
await iam.api.invariants.create(credential, {
  tenantId,
  name: 'Contractors never approve payments',
  subject: { attribute: { name: 'contractor', value: true } },
  action: 'payments:approve',
  resource: { type: 'ledger', id: 'main' },
  expect: 'deny',
  mode: 'enforce',
});
```

An enforced invariant is re-checked around every access-changing operation; a binding, group change, role edit, package assignment, or configuration apply that would newly break it is refused with `INVARIANT_VIOLATION` and rolled back. Violations that predate enforcement are reported but do not block unrelated work. Monitored invariants only report: schedule `iam.checkInvariants()` (`better-iam monitor-invariants`) to record `invariant:broken` / `invariant:restored` audit events once per change and route them to a webhook, and gate CI with `better-iam check-invariants --tenant ID --fail-on-broken`. Invariants and agreements are part of [configuration as code](policies.md#configuration-as-code), so they can live in version control with the roles they protect.

## 5. Agree: terms of use

```ts
await iam.api.agreements.create(credential, {
  tenantId,
  name: 'Acceptable use',
  content: 'Use company systems for work. Report incidents within 24 hours.',
  reacceptAfterDays: 365,
});
```

Members see what they owe with `agreements.listMine` and accept with `agreements.accept` (the console shows a banner; `useAgreements` does the same in React and Vue apps). Enforcement is an ordinary policy statement, so it composes with everything else:

```json
{
  "effect": "deny",
  "actions": ["documents:*"],
  "resources": ["*"],
  "conditions": { "NumericGreaterThan": { "principal.pendingAgreements": 0 } }
}
```

Publishing a new version (`agreements.update({ newVersion: true })`, or a content change through configuration apply) asks everyone to accept again.

## 6. Help people help themselves

When your application refuses something, ask what the person could do about it:

```ts
const { paths } = await iam.api.accessPaths.find({ token }, { tenantId, action, resource });
```

Each path — step up to MFA, accept pending terms, activate an eligible (just-in-time) role, request a requestable package — is verified by simulating it in a rolled-back transaction, so the list never promises access that would still be refused. An empty list means only an administrator can help. `useAccessPaths` wraps it for React and Vue.

## Scheduling

| Job                  | Call                                   | CLI                      | Suggested cadence |
| -------------------- | -------------------------------------- | ------------------------ | ----------------- |
| Write buffered usage | automatic (every minute) and on demand | —                        | —                 |
| Invariant monitor    | `iam.checkInvariants()`                | `monitor-invariants`     | hourly            |
| Role-mining snapshot | `roleMining.suggest` as a token holder | `mine-roles --tenant ID` | weekly            |
| Guardrail gate in CI | `invariants.run`                       | `check-invariants`       | every deploy      |
