# serviceAccounts

Service accounts are identities for machines: a deploy pipeline, a billing worker, a partner integration. They live in
a tenant's directory next to people (`kind: 'service'`), receive access the same way through role bindings, groups,
and relationships, and authenticate only with [API keys](/docs/reference/api/credentials), never by signing in.
Giving each integration its own account keeps its access reviewable and revocable without touching anyone's personal
access.

## How service accounts relate to identities

This group is a focused view of the identity directory: it only ever returns or changes identities of kind
`service`, and it is authorized with the same `iam:identities:*` actions as
[`identities`](/docs/reference/api/identities), checked on the tenant for `create` and `list` and on `iam/{identityId}`
for everything else. When an account calls
the API with a key, policies see it as `principal.kind: 'service'`, so a statement can treat machines differently
from people. Bind roles to an account with
[`bindings.create`](/docs/reference/api/bindings#create), and remove one completely with
[`identities.offboard`](/docs/reference/api/identities#offboard) when you need a successor for the resources it owns.

## Scheduled deactivation

An `expiresAt` (epoch milliseconds, at most ten years ahead) gives an account a deadline, which suits a vendor
integration or a migration job. From that instant every key of the account is refused. The purge worker
(`iam.purgeDeleted()`, see [scheduled jobs](/docs/operations/jobs)) then disables the account, deletes its keys, and
records `identity:expire`. If you extend or clear the deadline before the worker runs, the existing keys work again;
after it has run, extend or clear the deadline, enable the account with [`setStatus`](#setstatus), and issue new
keys. See
[time-bound identities](/docs/guides/privileged-access/lifecycle#time-bound-identities).

## create

Creates a service account in the tenant, optionally with a date after which it is deactivated.

- **Permission:** `iam:identities:create` on the tenant, and the caller must hold an active grant authority.
- **Audited as:** `iam:identities:create`.
- **Errors:** `GRANT_AUTHORITY_REQUIRED` when the caller holds no grant authority; `LIMIT_EXCEEDED` at the tenant's
  service account limit; `INVALID_INPUT` for an empty name, a description over 512 characters, or an `expiresAt` that
  is not in the future or is more than ten years away.

The new account is active but holds no access until you bind roles to it or add it to groups. Automatic
[access package](/docs/guides/privileged-access/access-packages) rules are evaluated for it right after creation, so
a rule that matches service accounts grants its package at once. Then issue a key with
[`credentials.create`](/docs/reference/api/credentials#create).

```ts
const account = await iam.api.serviceAccounts.create(credential, {
  tenantId,
  name: 'Billing sync',
  description: 'Nightly export to the finance system',
  expiresAt: Date.parse('2027-06-30T00:00:00Z'),
});
```

## delete

Deletes a service account, revoking its keys and removing every grant it held.

- **Permission:** `iam:identities:delete` on the account, with recent authentication.
- **Audited as:** `iam:identities:delete`, plus `identity:delete` with `metadata.kind` set to `service`.
- **Errors:** `NOT_FOUND` when the id is not a service account of this tenant; `CONFLICT` when it is already deleted;
  `INVALID_INPUT` when an account tries to delete itself; `RECENT_AUTH_REQUIRED`; `IMPERSONATION_RESTRICTED`.

In one transaction the account's keys and assumed-role sessions end, its role bindings, group memberships,
activations, package assignments, relationships, and boundary are removed, pending access requests are cancelled, and
any grant authority it held is revoked. The account stays as a deleted record, visible with `list({ includeDeleted })`,
so the audit log keeps resolving its id.

## get

Returns one service account by id.

- **Permission:** `iam:identities:read` on the account.
- **Audited as:** `iam:identities:read`.
- **Errors:** `NOT_FOUND` when the id is not a service account of this tenant (people are not returned here).

A deleted account is still returned, with `status: 'deleted'`.

## list

Lists the tenant's service accounts, without deleted ones unless you ask for them.

- **Permission:** `iam:identities:read` on the tenant.
- **Audited as:** `iam:identities:read`.

Pass `includeDeleted: true` to include deleted accounts, for example when resolving old audit entries. Combine it with
[`credentials.list`](/docs/reference/api/credentials#list) to review which accounts hold keys and when they were
last used.

## setStatus

Disables a service account, ending all its access at once, or enables it again.

- **Permission:** `iam:identities:update` on the account, with recent authentication.
- **Audited as:** `iam:identities:update`.
- **Errors:** `INVALID_TRANSITION` (409) when enabling an account whose `expiresAt` has passed; `NOT_FOUND` when the
  id is not a service account of this tenant or was deleted; `INVALID_INPUT` for a status other than `active` or
  `disabled`; `INVARIANT_VIOLATION` when an enforced
  [access invariant](/docs/guides/governance/change-safety) would newly fail; `RECENT_AUTH_REQUIRED`;
  `IMPERSONATION_RESTRICTED`.

Disabling deletes every API key the account holds and every role session it assumed, while its bindings and
memberships stay in place. Use it to contain a leaked key or pause an integration. Enabling the account again does not
bring the keys back: issue new ones. To re-enable an expired account, first extend or clear `expiresAt` with
[`update`](#update), so nobody quietly turns a finished integration back on.

## update

Renames a service account, changes its description or directory attributes, or schedules or clears its deactivation.

- **Permission:** `iam:identities:update` on the account.
- **Audited as:** `iam:identities:update`.
- **Errors:** `INVALID_INPUT` when nothing is given to change, an attribute is not declared in
  `permissions.identityAttributes` or has the wrong type, or `expiresAt` is invalid; `NOT_FOUND` when the id is not a
  service account of this tenant or was deleted; `INVARIANT_VIOLATION` when an enforced access invariant would newly
  fail.

`attributes` replaces the account's whole attribute set; policies read them as `principal.{name}`. Pass
`expiresAt: null` to make the account permanent. Automatic access package rules are re-evaluated for the account
afterwards, so an attribute change can add or remove package access.
