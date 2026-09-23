# bindings

Bindings give a role to a person, service account, or group, and control when that role actually applies. A role
grants nothing until it is bound: a binding links one role to one subject, and the subject holds the role for as
long as the binding says. A binding can be standing (always on), temporary, future-dated, limited to recurring
hours, or eligible, which means the subject may take the role just in time, for a bounded period, with a reason, MFA,
or a second person's approval. This group creates and changes bindings, runs that activation and approval flow, and
answers "who holds what".

## Why a binding needs grant authority

Every binding is created under a [grant authority](/docs/guides/authorization/roles#grant-authorities): the
delegated right to hand out access, with a ceiling on what it may ever grant. Pass `authorityId` to pick one of
your own authorities; otherwise the server uses your root-issued authority (root administrators) or your first
active delegated authority. A caller with no active authority gets `GRANT_AUTHORITY_REQUIRED`. The binding stores
the authority's id, and that matters in three ways:

- **Ceiling.** Whatever the role says, the binding grants no more than the ceilings of its authority chain allow.
  They are applied as boundaries every time a request is evaluated.
- **Revocation.** When the authority, or any authority above it, is
  [revoked](/docs/reference/api/authorities#revoke), the binding grants nothing from the next request on.
- **Ownership.** Only the holder of that authority, or root, may update or delete the binding or revoke activations
  of it. A junior administrator cannot undo a senior administrator's grants.

The permission and the authority answer different questions. `iam:bindings:create` on `iam/{roleId}` decides which
roles you may bind; the authority caps what those bindings can reach.

## When a binding applies

A binding without dates or rules is standing: it applies until someone removes it. Four options narrow it without
changing the role:

| Option | Effect |
| --- | --- |
| `expiresAt` | Epoch milliseconds, in the future and at most ten years ahead. The binding stops granting at that instant, is left out of listings unless you pass `includeExpired: true`, and is deleted with its activations by the purge worker ([`purgeDeleted`](/docs/reference/api#purgedeleted)). |
| `startsAt` | Epoch milliseconds, not in the past and at most ten years ahead, before `expiresAt`. The binding is listed with its start but grants nothing until then. Separation-of-duties rules already count it. |
| `window` | `{ from, to, timeZone, days? }`: `HH:MM` times in an IANA time zone, and weekdays 0 (Sunday) to 6 (every day by default). Outside the window the binding grants nothing. A window whose end is not after its start wraps past midnight and counts as the day it starts on. |
| `eligible` | The binding grants nothing until its subject activates it, for a bounded time. |

A group binding reaches every live member of the group, so membership changes grant and remove the role too. See
[temporary access](/docs/guides/authorization/temporary-access) for dates and windows.

## Just-in-time activation

An eligible binding records that its subject _may_ hold a role. The subject activates it with `activate` when they
need the role, and it lapses on its own. That keeps administrator and production roles out of everyday sessions
while every elevation leaves a record with a reason. The full walkthrough is in
[just-in-time elevation](/docs/guides/privileged-access/elevation).

Each eligible binding carries its activation rules:

| Setting | Effect |
| --- | --- |
| `maxActivationMs` | The longest activation, from one minute to seven days. Defaults to one hour. |
| `requireJustification` | The activation must state a reason (at most 2048 characters). It is stored on the activation and in the audit trail. |
| `requireMfa` | Only a session that completed MFA may activate. |
| `requireApproval` | Activation becomes a request that an approver grants or denies. |
| `approverGroupId` | Only live members of this group (or root) may decide, and they are emailed each request. |
| `managerApproval` | The requester's manager (`managerId`) may decide as well, and is emailed each request. |

Passing any of these for a binding that is not eligible fails with `INVALID_INPUT`; explicit `false` flags are
accepted, so forms can send every checkbox. The tenant's
[access policy](/docs/reference/api/tenants#setaccesspolicy) tightens every eligible binding at once: a rule applies
when either the binding or the policy sets it, the maximum length is the smaller of the two, and the policy's
`approvalLifetimeMs` (one day by default) is how long a request waits for a decision.

There is one activation record per binding and person. It starts `active` (or `pending` when approval is required),
and it ends when it reaches `expiresAt`, when its holder calls `deactivate`, when an administrator calls
`revokeActivation`, or when the person leaves the group, the binding or role is deleted, or eligibility is turned
off. An activation belongs to the person, not the session: signing out does not end it. An access window on the
binding still applies while it is active.

Who may elevate and who may approve are ordinary permissions: `iam:bindings:activate` and `iam:bindings:approve` on
`iam/{roleId}`. The usual setup is a Member role holding `iam:bindings:activate`, bound to a group everyone belongs
to, and an Approver role bound to the approver group.

## create

Gives a role to a person, service account, or group under your grant authority, optionally temporary, future-dated,
limited to a recurring window, or eligible for just-in-time activation.

- **Permission:** `iam:bindings:create` on the role (`iam/{roleId}`), plus an active grant authority.
- **Audited as:** `iam:bindings:create`.
- **Errors:** `PROTECTED_RESOURCE` for the protected Owner role; `NOT_FOUND` when the role, group, approver group, or
  identity is not in this tenant, or the identity is deleted; `GRANT_AUTHORITY_REQUIRED` when you hold no active
  grant authority; `ACCESS_DENIED` when `authorityId` names an authority that is not yours or is revoked;
  `INVALID_INPUT` for an invalid subject type, date, or window, a `startsAt` that is not before `expiresAt`, or
  activation settings on a binding that is not eligible; `CONFLICT` when the subject already has a binding of this
  role under the same authority; `SOD_CONFLICT` when the binding would give someone a combination of roles a
  [separation-of-duties rule](/docs/guides/authorization/separation-of-duties) forbids; `INVARIANT_VIOLATION` when it
  would newly break an enforced [access invariant](/docs/reference/api/invariants).

Bind roles to groups where you can: people then gain and lose the role as they join and leave, without anyone
editing bindings. The Owner role is never bound this way; ownership changes go through
[`identities.setOwner`](/docs/reference/api/identities#setowner). An expired binding that the purge worker has not
removed yet still counts for `CONFLICT`; extend it with `update` instead of creating a new one.

```ts
// A contractor gets support access on weekdays, starting next week, for 90 days.
const startsAt = Date.now() + 7 * 86_400_000;
await iam.api.bindings.create(credential, {
  tenantId,
  roleId: support.id,
  subjectType: 'identity',
  subjectId: contractor.id,
  startsAt,
  expiresAt: startsAt + 90 * 86_400_000,
  window: { from: '09:00', to: '17:00', timeZone: 'Europe/Berlin', days: [1, 2, 3, 4, 5] },
});

// The on-call group may take the incident-responder role for up to two hours, with a reason and MFA.
await iam.api.bindings.create(credential, {
  tenantId,
  roleId: responder.id,
  subjectType: 'group',
  subjectId: onCall.id,
  eligible: true,
  maxActivationMs: 2 * 60 * 60 * 1000,
  requireJustification: true,
  requireMfa: true,
});
```

## update

Changes a binding's start, expiry, access window, or eligibility settings in place.

- **Permission:** `iam:bindings:create` on the role (`iam/{roleId}`), and the binding's own grant authority (or
  root).
- **Audited as:** `iam:bindings:create`.
- **Errors:** `ACCESS_DENIED` ("Cannot mutate a higher authority binding") when another administrator's authority
  issued the binding; `PROTECTED_RESOURCE` for an Owner binding; `INVALID_INPUT` when nothing is given to change, or
  under the same date, window, and setting rules as `create`; `NOT_FOUND`; `SOD_CONFLICT` when extending an already
  expired binding would create a forbidden combination; `INVARIANT_VIOLATION`.

Pass `null` to clear `startsAt`, `expiresAt`, `window`, or `approverGroupId`. The binding keeps its id and its
authority. `eligible: false` turns an eligible binding into a standing one, drops its activation settings, and ends
every activation and pending request of it; `eligible: true` does the reverse, so the subject stops holding the role
until they activate it. Editing a binding that an [access package](/docs/guides/privileged-access/access-packages)
created takes it over: revoking the package no longer removes it.

```ts
// Extend a contractor's access by 30 days and drop the business-hours limit.
await iam.api.bindings.update(credential, {
  tenantId,
  bindingId,
  expiresAt: Date.now() + 30 * 86_400_000,
  window: null,
});
```

## delete

Removes a binding and every activation of it, so its subject stops holding the role at the next request.

- **Permission:** `iam:bindings:delete` on the binding (`iam/{bindingId}`), and the binding's own grant authority
  (or root).
- **Audited as:** `iam:bindings:delete`.
- **Errors:** `ACCESS_DENIED` when another administrator's authority issued the binding; `PROTECTED_RESOURCE` for an
  Owner binding; `NOT_FOUND` when the binding is not in this tenant; `INVARIANT_VIOLATION` when removing it would
  break an enforced invariant that expects someone to keep access.

To take a group's role away from one person, remove them from the group instead; deleting the group binding
removes the role from every member.

## list

Lists the tenant's bindings, filtered by role, subject, eligibility, or upcoming expiry.

- **Permission:** `iam:bindings:read` on the role (`iam/{roleId}`) when you filter by `roleId`, otherwise on the
  subject (`iam/{subjectId}`) when you filter by `subjectId`, otherwise on the tenant.
- **Audited as:** `iam:bindings:read`.
- **Errors:** `INVALID_INPUT` for an unknown `subjectType`, a non-boolean `eligible`, or an invalid `expiresBefore`.

Expired bindings are left out unless you pass `includeExpired: true`; future-dated ones are included.
`eligible: true` keeps only eligible bindings and `eligible: false` only standing ones, which is how you audit
standing privileged access. `expiresBefore` keeps temporary bindings that end at or before that time, for "what
ends this month?" reports. Group bindings are returned as stored, not expanded to members: use
[`identities.listBindings`](/docs/reference/api/identities#listbindings) for one person's effective roles and
[`roles.listBindings`](/docs/reference/api/roles#listbindings) for holders with names.

```ts
const endingSoon = await iam.api.bindings.list(credential, {
  tenantId,
  expiresBefore: Date.now() + 14 * 86_400_000,
});
```

## activate

Activates an eligible binding for yourself so you hold its role for a limited time, or records an approval request
when the binding requires one.

- **Permission:** `iam:bindings:activate` on the role (`iam/{roleId}`), from your own ordinary session of the
  tenant. The binding must apply to you, directly or through a group you are a live member of.
- **Audited as:** `iam:bindings:activate`, plus `binding:activate` (with `activationId`, `roleId`, `expiresAt`, and
  the justification) or, when approval is required, `binding:activation-requested`.
- **Errors:** `INVALID_TRANSITION` when the binding is not eligible, has not started, or has expired, or when it
  requires approval from named approvers and none of them is active (an empty approver group and no active manager);
  `ACCESS_DENIED` when the binding does not apply to you; `INVALID_INPUT` from an assumed-role session or a session
  of another tenant, without a required justification, or for a `durationMs` outside one minute to the effective
  maximum; `MFA_REQUIRED` when MFA is required and your session did not complete it; `IMPERSONATION_RESTRICTED` from
  a "view as" session; `CONFLICT` while you already hold a live activation or a waiting request for this binding;
  `INVARIANT_VIOLATION`.

`durationMs` defaults to the effective maximum: the binding's `maxActivationMs`, capped by the tenant's access
policy. Without approval, the result has `status: 'active'` and `active: true`, and the role applies from the next
request until `expiresAt`. With approval, the result has `status: 'pending'`; it lapses after the tenant's
`approvalLifetimeMs` (24 hours by default) unless someone decides. When the deployment sends email, the approver
group's live members and, with `managerApproval`, your manager receive an `activation-request`. An earlier activation that ended or was denied is replaced,
so you can ask again after a refusal.

```ts
const activation = await iam.api.bindings.activate(credential, {
  tenantId,
  bindingId,
  durationMs: 30 * 60 * 1000,
  justification: 'INC-4211: restart the payments worker',
});
if (activation.status === 'pending') {
  // Waiting for an approver; bindings.listMine shows it as pendingActivation.
}
```

## approveActivation

Grants a pending activation request, so the requester holds the role from now until the approved duration ends.

- **Permission:** `iam:bindings:approve` on the role (`iam/{roleId}`). When the binding names approvers, you must
  also be a live member of its approver group, the requester's manager (with `managerApproval`), or root.
- **Audited as:** `iam:bindings:approve`, plus `binding:activation-approved` with the new `expiresAt` and your note.
- **Errors:** `INVALID_TRANSITION` (409) when the request is no longer waiting (decided, withdrawn, or lapsed) or its
  binding is no longer eligible and live; `INVALID_INPUT` when you decide your own request, for a `durationMs`
  outside one minute to the effective maximum, or for a note over 2048 characters; `ACCESS_DENIED` when you are not
  one of the designated approvers; `IMPERSONATION_RESTRICTED` from a "view as" session; `NOT_FOUND`;
  `INVARIANT_VIOLATION`.

Without `durationMs`, the requester gets the duration they asked for, capped at the binding's effective maximum as
it stands now (the tenant policy may have tightened since the request). Your `durationMs` replaces the requested
one, for example to grant a shorter window than asked. The activation starts when you approve, not when it was
requested. The requester is emailed `activation-decided` when the deployment sends email. Because nobody decides
their own request and an impersonating administrator cannot decide in someone's name, approval gives you
two-person control.

```ts
await iam.api.bindings.approveActivation(credential, {
  tenantId,
  activationId,
  durationMs: 45 * 60 * 1000,
  note: 'Approved for the change window',
});
```

## denyActivation

Refuses a pending activation request, optionally with a note for the requester.

- **Permission:** `iam:bindings:approve` on the role (`iam/{roleId}`), and designated-approver status when the
  binding names approvers.
- **Audited as:** `iam:bindings:approve`, plus `binding:activation-denied` with your note.
- **Errors:** `INVALID_TRANSITION` (409) when the request is no longer waiting or its binding is no longer eligible
  and live; `INVALID_INPUT` when you decide your own request or the note is over 2048 characters; `ACCESS_DENIED`
  when you are not a designated approver; `IMPERSONATION_RESTRICTED`; `NOT_FOUND`.

The request becomes `status: 'denied'` and grants nothing. It stays visible through
`listActivations({ status: 'denied' })` until the purge worker removes it. The requester is emailed
`activation-decided` with your note when the deployment sends email, and may ask again with `activate`.

## deactivate

Ends your own activation early, or withdraws your own pending request.

- **Permission:** `iam:bindings:activate` on the role (`iam/{roleId}`); only the person the activation belongs to.
- **Audited as:** `iam:bindings:activate`, plus `binding:deactivate` (with `cancelled: true` for a withdrawn
  request).
- **Errors:** `ACCESS_DENIED` when the activation belongs to someone else (administrators use `revokeActivation`);
  `NOT_FOUND`; `INVARIANT_VIOLATION`.

Step down when the work is done early: the role stops applying at the next request. The record is deleted, so you
can activate again later.

## revokeActivation

Ends someone else's activation or pending request immediately, for incident response.

- **Permission:** `iam:bindings:delete` on the binding (`iam/{bindingId}`), and the binding's own grant authority
  (or root), like deleting the binding.
- **Audited as:** `iam:bindings:delete`, plus `binding:deactivate` with `revoked: true` and the holder's
  `identityId`.
- **Errors:** `ACCESS_DENIED` when another administrator's authority issued the binding; `NOT_FOUND`;
  `INVARIANT_VIOLATION`.

Revoking ends the elevation, not the entitlement: the binding stays eligible and the person can activate it again.
To stop that, delete the binding or remove the person from its group. Revoking does not end the person's sessions;
use [`identities.revokeSessions`](/docs/reference/api/identities#revokesessions) for that.

## listActivations

Lists activations and activation requests, newest first, filtered by binding, person, role, or status.

- **Permission:** `iam:bindings:read` on the first of `bindingId`, `identityId`, or `roleId` you filter by
  (`iam/{id}`), otherwise on the tenant.
- **Audited as:** `iam:bindings:read`.
- **Errors:** `INVALID_INPUT` for a `status` other than `pending`, `active`, or `denied`.

Without `status`, the result is who is elevated right now: live activations only. `status: 'pending'` lists open
requests, `'active'` activations, and `'denied'` refusals (all of them, until the purge worker removes them).
`includeExpired: true` adds records that have ended or lapsed but are not yet purged. Each record carries `status`
and `active` (whether it grants at this moment).

## listApprovals

Lists the pending activation requests you may decide on, oldest first, with the role and the requester.

- **Permission:** `iam:bindings:approve` on the tenant. A request is included only when you also hold
  `iam:bindings:approve` on its role and are a designated approver where the binding names any.
- **Audited as:** `iam:bindings:approve`.

It never includes your own requests or requests that have lapsed. Use it to build an approver's inbox; each entry
carries `role` (id and name) and `requester` (id, name, and email).

## listMine

Lists your own bindings, direct and through groups, with any live activation or waiting request, so you can see
what you may elevate to.

- **Permission:** `iam:bindings:activate` on the tenant, from an ordinary session of the tenant.
- **Audited as:** `iam:bindings:activate`.
- **Errors:** `INVALID_INPUT` from an assumed-role session or a session of another tenant.

It needs no `iam:bindings:read`, so members see their own access without seeing everyone else's. Each entry is a
binding with `via` (`'identity'`, or `{ groupId }` for a group binding) and its `role`, plus `activation` (`id`,
`activatedAt`, `expiresAt`) while one is live, `pendingActivation` (`id`, `requestedAt`, `expiresAt`) while a request
waits, and `inWindow` for bindings with an access window. Standing and eligible bindings are both listed;
future-dated ones appear with their `startsAt`, and expired ones are left out.
