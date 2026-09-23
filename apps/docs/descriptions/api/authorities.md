# authorities

Grant authorities delegate the right to hand out access, with a ceiling on what anything granted under them may
ever allow. In a growing organization not every administrator should be able to grant everything: a support lead
should give support roles to their team but never make someone a tenant administrator. Every role, policy, and
binding records the authority it was created under, and that authority's ceiling bounds it for as long as it
exists. The guide is [grant authorities](/docs/guides/authorization/roles#grant-authorities).

## How delegation works

- **A ceiling is a boundary.** An authority's `ceiling` is a policy document. Whenever a grant issued under the
  authority is evaluated, the ceiling, and every ceiling above it in the chain, is applied as a boundary: whatever
  the role says, the result never exceeds them. Nothing is checked for containment when the authority is created;
  a child ceiling broader than its parent's is simply cut back by the parent at evaluation time.
- **Authorities form a chain.** A new authority is a child of one of your own, so delegation only ever narrows.
  Root administrators receive a root-issued, unrestricted authority automatically, and a tenant's first owner
  receives the authority their invitation carried.
- **Authority is not permission.** Holding an authority does not let anyone grant anything. They also need the
  permissions, such as `iam:bindings:create` on the roles they may bind. The two together mean "may bind these
  roles, and the result never exceeds this ceiling".
- **Revocation cascades.** Revoking an authority disables every binding, role, policy, and API key issued under it,
  and under every authority delegated from it, at the next request.
- **Edits stay with their authority.** Only the holder of the authority behind a binding, role, or policy, or root,
  may change or delete it.

Records carry the id of their authority as `authorityId`, and
[`identities.export`](/docs/reference/api/identities#export) lists the authorities a person holds.

## create

Delegates a new grant authority to an identity, bounded by a ceiling and by your own authority chain.

- **Permission:** `iam:authorities:create` on the recipient (`iam/{identityId}`), an active grant authority of your
  own to delegate from, and a recently authenticated session.
- **Audited as:** `iam:authorities:create`.
- **Errors:** `RECENT_AUTH_REQUIRED` when your sign-in is not recent or you call from temporary credentials such as
  a role session; `IMPERSONATION_RESTRICTED` from a "view as" session; `ACCESS_DENIED` when you issue authority to
  yourself (only root may) or `parentAuthorityId` names an authority that is not yours or is revoked;
  `GRANT_AUTHORITY_REQUIRED` when you hold no active authority; `INVALID_POLICY`, `INVALID_ACTION`, or
  `INVALID_RESOURCE_TYPE` when the ceiling does not validate against the catalog; `NOT_FOUND` when the identity is
  not in this tenant.

`parentAuthorityId` picks which of your authorities the new one hangs under; without it, your root-issued authority
(root) or your first active delegated authority is used. Give the person a role with the matching `iam:*`
permissions as well, or the authority lets them grant nothing.

```ts
// The support lead may hand out support roles, and nothing they grant can exceed tickets and customer reads.
const authority = await iam.api.authorities.create(credential, {
  tenantId,
  identityId: supportLead.id,
  ceiling: {
    version: 1,
    statements: [{ effect: 'allow', actions: ['tickets:*', 'customers:read'], resources: ['*'] }],
  },
});
```

## revoke

Withdraws a grant authority, so everything issued under it, and under authorities delegated from it, stops granting
at the next request.

- **Permission:** `iam:authorities:revoke` on the authority (`iam/{authorityId}`) and a recently authenticated
  session. You must hold the authority's parent (or be root), and you cannot revoke your own.
- **Audited as:** `iam:authorities:revoke`.
- **Errors:** `ACCESS_DENIED` ("Only superior authority can revoke this grant") when you do not hold the parent
  authority; `RECENT_AUTH_REQUIRED`; `IMPERSONATION_RESTRICTED`; `NOT_FOUND` when the authority is not in this
  tenant; `INVARIANT_VIOLATION` when the loss of access would break an enforced
  [access invariant](/docs/reference/api/invariants).

Use it when a delegated administrator changes teams or leaves; offboarding with
[`identities.offboard`](/docs/reference/api/identities#offboard) does it for you. Removing someone's administrator
role alone does not disable the access they provisioned; revoking their authority does. Revocation deletes nothing:
bindings, roles, and policies issued under the authority remain but grant nothing, and API keys issued under it are
denied on every check. There is no way to reinstate a revoked authority; delegate a new one and re-issue what is
still needed under it. The result is the authority with `revoked: true`.
