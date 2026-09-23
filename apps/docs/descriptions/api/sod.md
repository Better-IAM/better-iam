# sod

Separation-of-duties rules name roles that nobody may hold together, such as creating suppliers and approving
payments to them. Each role is fine on its own; the combination makes fraud or an unnoticed mistake possible.
Because roles reach people through many paths over time (direct bindings, groups, access requests, packages,
configuration), nobody sees such a combination forming. A rule makes Better IAM check for it on every operation that
can grant a role, and report the conflicts that already exist. The guide is
[separation of duties](/docs/guides/authorization/separation-of-duties).

## How rules are checked

A person holds a rule's role when they have a direct binding to it, a binding through a group they are a live
member of, an eligible (just-in-time) binding even before activating it, or a future-dated binding. Expired
bindings, lapsed memberships, and deleted identities do not count. Role inheritance is not expanded: name the roles
you actually bind.

A rule has one of two modes:

- **`prevent`** (the default): every operation that can grant a role (`bindings.create` and `bindings.update`, group
  membership changes, `identities.createMany`, access-request approval, access-package assignment and approved
  package requests, `config.apply`, and member-invitation acceptance) compares the tenant's conflicts before and
  after it runs. If it would create a new one, it fails with `SOD_CONFLICT` (409) and its transaction rolls back.
- **`detect`**: nothing is refused; conflicts are only reported by `violations` and by the access analysis, as
  high-severity `separation-of-duties` findings.

Conflicts that already existed never block unrelated work, so you can add a rule to a tenant that is not clean yet
and fix violations at your own pace. SCIM role mappings are not blocked; their conflicts appear in the reports.

Rule management is authorized on `iam/sod/*` (create, list, violations) and `iam/sod/{ruleId}` (update, delete), so
a compliance team can manage rules without other administrative rights.

## create

Declares 2 to 20 roles that nobody may hold together, and reports how many people already hold two of them.

- **Permission:** `iam:sod:manage` on `iam/sod/*`.
- **Audited as:** `iam:sod:manage`.
- **Errors:** `INVALID_INPUT` when `name` or `roleIds` is missing, fewer than 2 or more than 20 distinct roles are
  named, one of them is a protected Owner role, the `mode` is not `prevent` or `detect`, or the name (200
  characters) or description (1000) is too long; `NOT_FOUND` when a role is not in this tenant.

The result is the stored rule plus `existingViolations`, the number of conflicts that already exist. Creating a
rule never fails because of them. To measure a rule's impact before enforcing it, create it with `mode: 'detect'`
and switch to `prevent` with `update` later.

```ts
const rule = await iam.api.sod.create(credential, {
  tenantId,
  name: 'Supplier creation vs payment approval',
  roleIds: [supplierAdmin.id, paymentApprover.id],
  description: 'Finance controls policy, section 4.2',
});
// rule.existingViolations: people who already hold both roles
```

## update

Changes a rule's name, description, roles, or mode.

- **Permission:** `iam:sod:manage` on `iam/sod/{ruleId}`.
- **Audited as:** `iam:sod:manage`.
- **Errors:** `NOT_FOUND` when the rule is not in this tenant; `INVALID_INPUT` under the same rules as `create`.

Only the fields you pass change; `roleIds` replaces the whole list. Switching to `prevent` takes effect for the next
granting operation, and conflicts that exist at that moment still do not block unrelated work.

## delete

Removes a rule, so the combination is no longer checked or reported.

- **Permission:** `iam:sod:manage` on `iam/sod/{ruleId}`.
- **Audited as:** `iam:sod:manage`.
- **Errors:** `NOT_FOUND` when the rule is not in this tenant.

## list

Lists the tenant's rules, newest first.

- **Permission:** `iam:sod:read` on `iam/sod/*`.
- **Audited as:** `iam:sod:read`.

## violations

Lists everyone who currently holds two or more roles of a rule, with names for review screens.

- **Permission:** `iam:sod:read` on `iam/sod/*`.
- **Audited as:** `iam:sod:read`.

Both `prevent` and `detect` rules are covered; pass `ruleId` to check one rule (an unknown id returns an empty
list). Each entry names the rule (`ruleId`, `ruleName`, `mode`), the person (`identityId`, and `identityName`, their
email or else their name), and the conflicting roles (`roleIds`, `roleNames`). Disabled identities are included,
because they can be re-enabled. To fix a violation, remove one of the conflicting grants: delete a binding with
[`bindings.delete`](/docs/reference/api/bindings#delete), remove the person from the group that carries the role,
or revoke the access package that granted it.

```ts
const violations = await iam.api.sod.violations(credential, { tenantId, ruleId: rule.id });
```
