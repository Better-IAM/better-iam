# accessRequests

Access requests let members ask for specific roles instead of asking an administrator to bind them by hand. A
member names up to 20 roles with a justification and an optional duration; a reviewer approves or denies, and
approval creates the bindings under the reviewer's own grant authority, so a reviewer can never grant more than they
could bind directly.

## Request lifecycle

A request starts `pending` and ends in exactly one of `approved`, `denied`, `cancelled` (by the requester, or when
the requester is offboarded or deleted), or `expired`. Two times matter:

- **How long a request waits.** The request's `expiresAt` is when a pending request lapses: `accessRequests.lifetimeMs`
  after it was made (seven days by default; a
  [deployment option](/docs/operations/deployment/configuration) between one minute and 365 days). A lapsed request
  is reported as `expired` at once and marked so in storage by the purge worker (`iam.purgeDeleted()`).
- **How long the access lasts.** `durationSeconds` (at least 60, at most `accessRequests.maxDurationSeconds`, 90
  days by default) sets the end of the granted bindings, counted from approval. The request records it as
  `grantExpiresAt`. Without a duration the bindings are permanent.

Approved bindings are ordinary role bindings tagged with `accessRequestId`. They end at `grantExpiresAt`, or when an
administrator removes them with [`bindings.delete`](/docs/reference/api/bindings#delete); the request itself only
records the decision. No notifications are sent: reviewers find work with `list({ status: 'pending' })`.

Use access requests for ad hoc roles. For a curated bundle of roles and groups with designated approvers, use
requestable [access packages](/docs/reference/api/packages#request) instead.

## approve

Approves a pending request, binding each requested role to the requester under your own grant authority.

- **Permission:** `iam:access-requests:review` on the request, plus `iam:bindings:create` on each requested role
  and a grant authority, exactly as [`bindings.create`](/docs/reference/api/bindings#create) requires.
- **Audited as:** `iam:access-requests:review`, plus `access-request:approve` with the requester, roles, binding IDs,
  and `grantExpiresAt`.
- **Errors:** `INVALID_TRANSITION` (409) when the request is no longer pending, including when it has lapsed;
  `ACCESS_DENIED` when you are the requester or cannot bind one of the roles; `INVALID_IDENTITY` when the requester
  is not active; `NOT_FOUND` when the request, the requester, or a role is gone; `INVALID_INPUT` for a
  `durationSeconds` out of range; `GRANT_AUTHORITY_REQUIRED` without a grant authority; `SOD_CONFLICT` when the roles
  would create a [separation-of-duties](/docs/guides/authorization/separation-of-duties) conflict;
  `INVARIANT_VIOLATION` when they would break an enforced invariant.

`durationSeconds` overrides the duration the requester asked for; the bindings end that long after approval. If the
requester already holds one of the roles through a binding under your authority, that binding is reused and its end
replaced by the approved one (removed, when no duration applies). The optional `note` is stored on the request.

```ts
await iam.api.accessRequests.approve(reviewerCredential, {
  tenantId,
  requestId,
  durationSeconds: 8 * 60 * 60, // one working day instead of the week they asked for
  note: 'Approved for the incident review.',
});
```

## cancel

Withdraws one of your own pending requests.

- **Permission:** `iam:access-requests:create` on the request, and you must be the requester.
- **Audited as:** `iam:access-requests:create`.
- **Errors:** `ACCESS_DENIED` when the request is someone else's; `INVALID_TRANSITION` when it is no longer pending;
  `NOT_FOUND` when it is not in this tenant.

## create

Asks for one or more roles for yourself, optionally for a limited time.

- **Permission:** `iam:access-requests:create` on the tenant, from an ordinary session of that tenant.
- **Audited as:** `iam:access-requests:create`.
- **Errors:** `INVALID_INPUT` from a role session or another tenant's session, for zero or more than 20 roles, or a
  `durationSeconds` out of range; `PROTECTED_RESOURCE` for an owner role; `NOT_FOUND` when a role is not in this
  tenant; `CONFLICT` when a pending request for the same set of roles exists; `TOO_MANY_REQUESTS` (429) when you
  already have 20 pending requests; `TENANT_INACTIVE` when the tenant is not active.

Nothing is granted until a reviewer approves. `justification` (up to 2048 characters) is shown to reviewers. Grant
`iam:access-requests:create` to every member, for example through a group everyone belongs to, and
`iam:access-requests:review` to the people who decide.

```ts
const request = await iam.api.accessRequests.create(memberCredential, {
  tenantId,
  roleIds: [supportAdminRole.id],
  justification: 'Covering the support rotation this week',
  durationSeconds: 7 * 24 * 60 * 60,
});
// request.status === 'pending'; request.expiresAt is when it lapses if nobody decides
```

## deny

Refuses a pending request, with an optional note for the requester.

- **Permission:** `iam:access-requests:review` on the request.
- **Audited as:** `iam:access-requests:review`, plus `access-request:deny` with the requester and roles.
- **Errors:** `INVALID_TRANSITION` when the request is no longer pending; `NOT_FOUND` when it is not in this tenant.

## get

Returns one request.

- **Permission:** `iam:access-requests:read` on the request.
- **Audited as:** `iam:access-requests:read`.
- **Errors:** `NOT_FOUND` when the request is not in this tenant.

A pending request past its lifetime is returned as `expired`.

## list

Lists the tenant's requests, newest first, optionally by status or requester.

- **Permission:** `iam:access-requests:read` on the tenant.
- **Audited as:** `iam:access-requests:read`.
- **Errors:** `INVALID_INPUT` for an unknown `status`.

The `status` filter matches the stored status, so until the purge worker runs, `status: 'pending'` can include
lapsed requests, which are reported as `expired`.

## listMine

Lists your own requests, newest first, optionally by status.

- **Permission:** `iam:access-requests:create` on the tenant, so anyone who may ask can see their own requests.
- **Audited as:** `iam:access-requests:create`.
- **Errors:** `INVALID_INPUT` for an unknown `status`.
