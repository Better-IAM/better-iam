# invariants

Access invariants are guardrails: statements about who must never, or must always, be able to perform an action on
a resource. "Contractors can never approve payments" and "the on-call group can always restart production" should
hold whatever roles, policies, and groups say, but nobody re-checks every such rule by hand after each change. An
invariant writes the rule down once and Better IAM checks it: on demand, on a schedule, and, in `enforce` mode,
around every change to access, refusing any change that would break it. The guide is
[change safety](/docs/guides/governance/change-safety).

## How an invariant is evaluated

An invariant names a `subject`, an `action`, a `resource`, and what to `expect`:

- `subject` is exactly one of `{ identityId }`, `{ groupId }` (its live members), `{ attribute: { name, value } }`
  (identities whose declared attribute equals the value), or `{ everyone: true }`. Only active identities whose
  scheduled deactivation has not passed are evaluated.
- `expect: 'deny'` means nobody in the subject may be allowed; `expect: 'allow'` means everyone in it must be.
- Each person is evaluated like [`policies.simulate`](/docs/reference/api/policies#simulate), with the ordinary
  evaluator, so conditions, boundaries, ceilings, relationships, and activations count. `assumeMfa` (default
  `true`) evaluates them as MFA-verified, the most they can reach.

A person the evaluation disagrees with is a violation, reported with the decision reason. Reports stop at 500
people per invariant (`truncated: true`); enforcement evaluates everyone. An invariant whose identity, group, or
resource no longer exists reports an `error` instead of a result.

## Monitor and enforce

`monitor` (the default) only reports. `enforce` also guards changes: the tenant's enforced invariants are evaluated
before and after every operation that can change access, including role and policy edits and deletions, binding
changes, just-in-time activation and approval, group membership changes, identity changes, package assignment,
configuration apply, relationship and resource changes, authority revocation, and role assumption. When the
operation newly breaks an invariant, or leaves it impossible to evaluate (for example by deleting the group it
names), it fails with `INVARIANT_VIOLATION` (409) and its transaction rolls back. Violations that already existed do
not block unrelated work, so you can switch an invariant to `enforce` while it is still broken.

Changes made outside the operation envelope, such as scheduled jobs, inbound SCIM provisioning, and members
accepting agreements, are not guarded. Schedule [`iam.checkInvariants`](/docs/reference/api#checkinvariants) (CLI
`monitor-invariants`) to catch those: it stores each invariant's `lastCheck` and records `invariant:broken` and
`invariant:restored` audit events once per change, which a webhook subscribed to `invariant:*` can route.

## create

Stores an invariant and returns it with its current result.

- **Permission:** `iam:invariants:manage` on the tenant.
- **Audited as:** `iam:invariants:manage`.
- **Errors:** `INVALID_INPUT` for a missing or overlong name (100 characters), a `subject` that is not exactly one
  of the four shapes, an undeclared identity attribute or a value of the wrong type, or an invalid `expect`, `mode`,
  or `assumeMfa`; `INVALID_ACTION` when the action is not in the catalog; `NOT_FOUND` when the named identity,
  group, or resource does not exist; `RESOURCE_RESOLVER_REQUIRED` for an application-owned resource type without a
  resolver; `CONFLICT` when an invariant with the same name (ignoring case) exists; `LIMIT_EXCEEDED` when the tenant
  already has 100 invariants.

The resource must resolve now, because an invariant over a resource that does not exist could never be evaluated.
The returned `result` shows at once whether the invariant holds; creating one in `enforce` mode succeeds even when it
is already broken.

```ts
const { invariant, result } = await iam.api.invariants.create(credential, {
  tenantId,
  name: 'Contractors never approve payments',
  subject: { attribute: { name: 'contractor', value: true } },
  action: 'payments:approve',
  resource: { type: 'ledger', id: 'main' },
  expect: 'deny',
  mode: 'enforce',
});
// result.passed, result.violations: [{ identity: { id, name }, reason }]
```

## update

Changes any field of an invariant and returns it with its new result.

- **Permission:** `iam:invariants:manage` on the invariant (`iam/{invariantId}`).
- **Audited as:** `iam:invariants:manage`.
- **Errors:** `NOT_FOUND` when the invariant is not in this tenant; otherwise the same as `create`.

Fields you leave out keep their values; `description: ''` removes the description. Use it to switch between
`monitor` and `enforce`, or to point an invariant at a new group or resource before deleting the old one.

## delete

Deletes an invariant, ending its monitoring and enforcement.

- **Permission:** `iam:invariants:manage` on the invariant (`iam/{invariantId}`).
- **Audited as:** `iam:invariants:manage`.
- **Errors:** `NOT_FOUND` when the invariant is not in this tenant.

An enforced invariant blocks deleting the group or resource it names; delete or change the invariant first.

## list

Lists the tenant's invariants by name, with the outcome of the last scheduled check.

- **Permission:** `iam:invariants:read` on the tenant.
- **Audited as:** `iam:invariants:read`.

Each invariant carries `lastCheck` (`at`, `passed`, the violating identity ids, and an `error` message) once
`iam.checkInvariants` has run. For a fresh evaluation, call `run`.

## run

Evaluates every invariant, or one, against the current configuration and reports which pass.

- **Permission:** `iam:invariants:read` on the tenant, or on the invariant (`iam/{invariantId}`) when you pass
  `invariantId`.
- **Audited as:** `iam:invariants:read`.
- **Errors:** `NOT_FOUND` when `invariantId` is not in this tenant.

The result has `generatedAt`, a `summary` (`passed`, `failed`, and `errors` counts), and one entry per invariant
with `passed`, `evaluated`, `truncated`, the `violations`, and an `error` when it could not be evaluated. It changes
nothing: it does not update `lastCheck` or record audit events for broken invariants. In CI, run
[`check-invariants`](/docs/reference/cli#check-invariants) with `--fail-on-broken` after applying configuration.
