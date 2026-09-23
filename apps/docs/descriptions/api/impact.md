# impact

Impact previews show who would gain or lose which actions before you edit a role or policy or delete a role. A
role edit reaches everyone who holds the role, directly, through groups, and through every role that inherits it,
and the effect depends on conditions, ceilings, and boundaries that are hard to reason about by reading documents.
A preview answers "what happens if I make this change?" with the real evaluator, and tells you which
[access invariants](/docs/reference/api/invariants) the change would break or fix, without saving anything. The
guide is [change safety](/docs/guides/governance/change-safety).

## How a preview works

1. The server finds the affected roles: the changed role, or every role that attaches the changed policy, plus every
   role that inherits them, transitively.
2. It collects the holders: active identities (people and service accounts) bound to those roles, directly or
   through a live group membership, up to 200.
3. It evaluates each holder against each of your 1 to 10 `resources`, for every known action or the `actions` you
   list, then applies the change exactly as the real call would (same validation, same permission, same edit
   rights) and evaluates again.
4. It compares the invariants before and after, and rolls the transaction back.

Because the ordinary evaluator runs, conditions, authority ceilings, boundaries, access windows, and just-in-time
eligibility all count. An eligible holder without a live activation holds nothing before or after the change, so
they show no difference. The change is simulated, not made, so enforced invariants are reported here rather than
refused.

## preview

Simulates a role update, a policy document change, or a role deletion, and reports the actions each holder would
gain and lose per resource, plus the access invariants the change would break or fix.

- **Permission:** `iam:policies:simulate` on the tenant, plus what the real change needs: `iam:roles:update` or
  `iam:roles:delete` on the role, or `iam:policies:update` on the policy, and the edit rights of the grant
  authority that created it (or root).
- **Audited as:** `iam:policies:simulate`. The simulated change is not audited, because it never happens.
- **Errors:** `INVALID_INPUT` when `change` does not name exactly one of `role`, `policy`, or `deleteRole`, when
  `resources` does not hold 1 to 10 entries, or when `actions` does not hold 1 to 200; `INVALID_ACTION` for an
  action missing from the catalog; `ACCESS_DENIED` when you lack the permission or edit rights the change needs;
  `IMPERSONATION_RESTRICTED` from a "view as" session; `NOT_FOUND` when the role, policy, or a managed resource does
  not exist; and any error the real call would raise, such as `RESOURCE_IN_USE` for deleting a role that others
  inherit, `PROTECTED_RESOURCE`, or `INVALID_POLICY`.

`change` takes one of three shapes: `{ role: { roleId, ...update } }` with the fields
[`roles.update`](/docs/reference/api/roles#update) accepts, `{ policy: { policyId, document } }` for a new policy
document, or `{ deleteRole: roleId }`. `assumeMfa: true` evaluates holders as MFA-verified.

The result lists the affected `roles`, the number of holders `evaluated` (with `truncated: true` when more than
200 were skipped), and `identities`: only the holders whose access changes, each with `changes` per resource
(`gained` and `lost` action names). `gainedTotal` and `lostTotal` sum them up, and `invariants` lists those the
change would newly break (`broken`, with the new violations) or make pass again (`fixed`).

```ts
const preview = await iam.api.impact.preview(credential, {
  tenantId,
  change: { role: { roleId: approver.id, permissions: ['payments:read', 'payments:approve'] } },
  resources: [{ type: 'ledger', id: 'main' }],
});
// preview.identities: [{ identity: { id, name }, changes: [{ resource: 'ledger/main', gained: [...], lost: [...] }] }]
// preview.invariants.broken: guardrails the change would break
```
