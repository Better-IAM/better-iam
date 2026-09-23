# identities

Identities are the people and service accounts that sign in to a tenant, and this group manages them from
invitation to offboarding. Every identity belongs to exactly one tenant, and its email is unique only within that
tenant: another tenant may hold a separate identity with the same address. The group creates people directly or
through email invitations, reads their sessions, groups, and effective roles, changes their profile, status, and
ownership, answers data-subject requests, and removes access cleanly when someone leaves.

Service accounts (`kind: 'service'`) live in the same directory. You create them with
[`serviceAccounts.create`](/docs/reference/api/service-accounts#create), but reading, listing, disabling,
offboarding, and deleting them go through these methods and the same `iam:identities:*` actions. See
[tenants and identities](/docs/guides/concepts/tenants-and-identities) for the model.

## Invitations

An invitation lets an administrator decide what a new member receives, while the member proves they control the
address and chooses their own password. [`invite`](#invite) stores the email, optional roles and groups, and only a
hash of a single-use token, then queues a `member-invitation` email through the
[delivery outbox](/docs/operations/jobs). The token is sealed inside that message, so neither the inviter nor the
API response ever sees it. Your invitation page reads the token from the link and calls the public
[`acceptInvitation`](#acceptinvitation).

- **Lifetime.** An invitation lasts `onboarding.invitationLifetimeMs` (24 hours by default).
  [`resendInvitation`](#resendinvitation) issues a new token and lifetime and the earlier link stops working;
  [`revokeInvitation`](#revokeinvitation) cancels it. Accepted, revoked, and expired invitations fail with
  `INVITATION_INVALID`.
- **Authority.** Roles and groups are checked when you invite and applied when the person accepts, as bindings
  under the <Term id="authority">grant authority</Term> you held at invite time. That authority is re-validated at
  acceptance: if it was revoked in the meantime, the invitation can no longer be accepted.
- **Delivery.** Invitations need an email delivery callback (`authentication.sendEmail`); without one,
  `invite` and `resendInvitation` fail with `DELIVERY_REQUIRED`.
- **Limits.** The plan's member limit is checked at acceptance, not when you invite, so an invitation can fail with
  `LIMIT_EXCEEDED` if the tenant filled up in the meantime.

Organization owners are invited differently: [`tenants.create`](/docs/reference/api/tenants#create) sends an owner
invitation for a new tenant.

## Disabling, offboarding, and deleting

Four calls take access away, from lightest to heaviest:

| Call | Takes away | Keeps | Typical use |
| --- | --- | --- | --- |
| [`revokeSessions`](#revokesessions) | Sessions, API keys, remembered devices | The account and all its access | A lost device or a suspected stolen token |
| [`setStatus`](#setstatus) `disabled` | The ability to sign in or authenticate; sessions and keys end | Roles, groups, and attributes, which apply again when re-enabled | Leave of absence, an investigation |
| [`offboard`](#offboard) | Every grant: bindings, memberships, packages, activations, relationships, authorities, sessions, keys | A disabled record for retention | Someone leaves |
| [`delete`](#delete) | The record itself, with credentials and factors | A tombstone, so audit records still resolve | After your retention period |

An identity can also carry an `expiresAt` for contractors and temporary accounts. From that moment its credentials
are refused, and the retention worker (`purgeDeleted`) disables it, ends its sessions and activations, and records
`identity:expire`. An expired identity cannot be re-enabled until you extend or clear the date with
[`update`](#update), so nobody quietly turns a contractor back on. See
[time-bound identities](/docs/guides/privileged-access/lifecycle#time-bound-identities).

Two kinds of account are protected throughout. The last active owner of a tenant cannot be disabled, offboarded,
deleted, or demoted (`LAST_OWNER`), and the last active root administrator cannot be disabled, offboarded, or
deleted (`LAST_ROOT_ADMIN`). A root administrator's status, sessions, expiry, sign-in address, and password can be
changed only by a root administrator.

## acceptInvitation

Redeems a member invitation: creates the person's account with the invited email, applies the invitation's roles
and groups, and signs them in.

- **Permission:** None: public. The token from the invitation email is the proof.
- **Audited as:** `identity:invitation:accept`, with the new member as the actor and the inviter, roles, and groups
  in the metadata.
- **Errors:** `INVITATION_INVALID` when the token is unknown, already used, revoked, or expired, or the inviter's
  grant authority was revoked; `TENANT_UNAVAILABLE` when the tenant or one of its ancestors is not active;
  `INVALID_INPUT` when neither the call nor the invitation gives a name; `IDENTITY_EXISTS` when an account with that
  email was created in the meantime; `LIMIT_EXCEEDED` at the tenant's member limit; `WEAK_PASSWORD` or
  `BREACHED_PASSWORD` when the password fails the password rules; `NOT_FOUND` when one of the invitation's roles or
  groups was deleted since; `SOD_CONFLICT` when the invitation's roles together break a
  [separation-of-duties rule](/docs/guides/authorization/separation-of-duties).

The email counts as verified, because following the link proved control of the address. `name` overrides the name
the inviter suggested. The result is the new public identity plus either `{ token, session }` or an MFA challenge
(`mfaRequired: true`) when the tenant requires MFA; continue with the
[MFA flow](/docs/guides/authentication/mfa#completing-a-challenge). Over HTTP, a response that issues a session
also sets the session cookie. Everything happens in one transaction, so a failure leaves the invitation usable.

```ts
const result = await client.identities.acceptInvitation({
  tenantId: params.tenant,
  token: params.token,
  password: form.password,
});
if ('mfaRequired' in result) {
  // enroll or verify the second factor, then continue
}
```

## create

Creates a person in the tenant, optionally with a password, a manager, and a scheduled deactivation date.

- **Permission:** `iam:identities:create` on the tenant.
- **Audited as:** `iam:identities:create`.
- **Errors:** `IDENTITY_EXISTS` (409) when the email is already used in this tenant; `LIMIT_EXCEEDED` at the
  tenant's member limit; `WEAK_PASSWORD` or `BREACHED_PASSWORD` for a password the rules refuse; `INVALID_INPUT`
  for an `expiresAt` that is not in the future or is more than ten years ahead, or a manager who is not active;
  `NOT_FOUND` when the manager is not in this tenant; `INVARIANT_VIOLATION` when the new person would break an
  enforced [access invariant](/docs/guides/governance/change-safety).

The account starts active, with an unverified email and no roles. Without a password the person cannot sign in
with one: send them a reset link with [`requestPasswordReset`](#requestpasswordreset), or use [`invite`](#invite)
instead, which lets them choose it. `expiresAt` (epoch milliseconds) schedules deactivation. Declared attributes
are set with [`update`](#update) or [`createMany`](#createmany). After the call commits,
[automatic access-package rules](/docs/guides/privileged-access/access-packages#automatic-assignment) are
reconciled for the new person, so a matching package applies right away.

```ts
const contractor = await iam.api.identities.create(credential, {
  tenantId,
  email: 'sam@contractor.example',
  name: 'Sam Rivera',
  managerId: teamLeadId,
  expiresAt: Date.parse('2026-12-31T23:59:59Z'),
});
```

## createMany

Creates up to 100 people in one transaction, each with optional attributes, roles, groups, password, and expiry.

- **Permission:** `iam:identities:create` on the tenant. With roles, also `iam:bindings:create` on each role and an
  active grant authority; with groups, `iam:groups:update` on each group and authority over each of its role
  bindings.
- **Audited as:** `iam:identities:create`.
- **Errors:** `INVALID_INPUT` for an empty list, more than 100 entries, or an undeclared or mistyped attribute;
  `ACCESS_DENIED` without the right to grant one of the roles or fill one of the groups; `PROTECTED_RESOURCE` for
  the Owner role; `GRANT_AUTHORITY_REQUIRED` when roles are given and you hold no active grant authority;
  `IDENTITY_EXISTS`, `LIMIT_EXCEEDED`, `SOD_CONFLICT`, and `INVARIANT_VIOLATION` as for single creation. Any
  failure rejects the whole batch.

Use it for migrations and cohort onboarding. Roles are bound directly to each person under your grant authority and
group memberships are permanent. An entry's `expiresAt` is that identity's deactivation date, not an expiry for its
grants. Attributes are checked against `permissions.identityAttributes`. The rights to grant each role and fill
each group are checked once for the whole batch, so an import can never grant more than you could bind by hand.

```ts
const { identities } = await iam.api.identities.createMany(credential, {
  tenantId,
  identities: newHires.map((hire) => ({
    email: hire.email,
    name: hire.name,
    attributes: { department: hire.department }, // declared in permissions.identityAttributes
    groupIds: [everyoneGroupId],
  })),
});
```

## delete

Removes a person or service account for good, leaving a tombstone so audit records still name who acted.

- **Permission:** `iam:identities:delete` on the identity, with recent authentication.
- **Audited as:** `iam:identities:delete` and `identity:delete` (with the kind and former email).
- **Errors:** `CONFLICT` when the identity is already deleted; `INVALID_INPUT` when you try to delete yourself;
  `ACCESS_DENIED` for a root administrator unless you are root; `LAST_OWNER` or `LAST_ROOT_ADMIN` for the last
  active owner or root administrator; `RECENT_AUTH_REQUIRED` when your sign-in is not recent.

In one transaction it ends every session, API key, remembered device, and pending challenge; deletes role bindings,
group memberships, activations, package assignments and requests, relationships, boundaries, passkeys, MFA
enrollment, password history, and external-provider mappings; revokes the grant authorities the identity held and
its account links; cancels its pending access requests; and clears it as the manager of anyone who reported to it.
Revoking its grant authorities means grants it issued as a delegated administrator stop applying (see
[grant authorities](/docs/guides/authorization/roles#grant-authorities)).

The tombstone keeps the ID, name, and kind with `status: 'deleted'`. It has no sign-in email, phone, or password;
the former address is kept as `deletedEmail`. `list` leaves tombstones out unless asked, and `get` still returns
them. Unlike `offboard`, deletion hands nothing to a successor, so for leavers call [`offboard`](#offboard) first
and `delete` after your retention period.

## export

Returns everything the tenant stores about one identity as JSON, to answer a data-subject access request.

- **Permission:** `iam:identities:read` on the identity, with recent authentication. Audit events are included only
  when you also hold `iam:audit:read` on the tenant.
- **Audited as:** `iam:identities:read` and `identity:export` (with the kind and whether audit events were
  included).
- **Errors:** `RECENT_AUTH_REQUIRED` when your sign-in is not recent; `NOT_FOUND` when the identity is not in this
  tenant.

The export contains the public identity; its stored sessions and API keys without token hashes; whether MFA is
enabled; passkey identifiers and transports; external-provider subjects; effective role bindings; groups;
relationships; access requests; boundaries; grant authorities; account links; and SCIM links. With
`iam:audit:read` it adds the audit events the identity performed, newest first and at most 5,000, and
`auditIncluded` tells you which you got. Secrets, password hashes, and tokens are never included. Deleted
identities can be exported too, which helps when a request arrives after the account was removed.

## get

Returns one identity by ID, including the tombstone of a deleted identity.

- **Permission:** `iam:identities:read` on the identity.
- **Audited as:** `iam:identities:read`.
- **Errors:** `NOT_FOUND` when the identity is not in this tenant.

Password hashes are never returned.

## impersonate

Opens a short-lived "view as" session as a member, for support and troubleshooting, and returns its token.

- **Permission:** `iam:identities:impersonate` on the member, with recent authentication, and the tenant's
  [authentication policy](/docs/guides/authentication/tenant-policy) must set `allowImpersonation`.
- **Audited as:** `iam:identities:impersonate` and `identity:impersonate` (with the reason, the new session ID, and
  its expiry).
- **Errors:** `FEATURE_DISABLED` when the tenant does not allow impersonation; `ACCESS_DENIED` for an owner or root
  administrator; `INVALID_INPUT` for yourself, a service account, a missing reason, or a `durationMs` outside one
  minute to eight hours; `IMPERSONATION_RESTRICTED` unless you act through an ordinary session of your own;
  `MFA_REQUIRED` when the member requires MFA and your session did not complete it; `IP_NOT_ALLOWED` or
  `IP_BLOCKED` when the tenant's network rules refuse your address; `RECENT_AUTH_REQUIRED`.

The session lasts `durationMs` (one hour by default) and never outlives your own session. Each operation it
attempts is allowed only when both the member and you may perform it, and it cannot do anything that needs recent
authentication, assume roles, or grant OAuth consent. Every audit record it produces carries `impersonatorId`,
policies see `principal.impersonated`, and the member sees the session in their own session list. Over HTTP the
token is returned in the body only, never as a cookie, so keep it in a separate context such as a dedicated tab.
See [impersonation](/docs/guides/authentication/impersonation).

```ts
const { token, session } = await iam.api.identities.impersonate(credential, {
  tenantId,
  identityId: memberId,
  reason: 'Ticket 4821: export button missing',
  durationMs: 30 * 60_000,
});
```

## invite

Invites a person to the tenant by email, with roles and groups they receive when they accept.

- **Permission:** `iam:identities:create` on the tenant. With roles, also `iam:bindings:create` on each role and an
  active grant authority; with groups, `iam:groups:update` on each group and authority over each of its role
  bindings.
- **Audited as:** `iam:identities:create`.
- **Errors:** `DELIVERY_REQUIRED` without an email delivery callback; `IDENTITY_EXISTS` when the email already
  belongs to an identity in this tenant; `PROTECTED_RESOURCE` for the Owner role; `ACCESS_DENIED` without the
  right to grant one of the roles or fill one of the groups; `GRANT_AUTHORITY_REQUIRED` when roles or groups are
  given and you hold no active grant authority; `NOT_FOUND` for an unknown role or group.

The result has the invitation ID and expiry but never the token, which travels only in the email. `name` is a
suggestion the person can change when accepting. Nothing is granted until acceptance; see
[Invitations](#invitations). Inviting the same address again does not cancel an earlier invitation, so use
[`resendInvitation`](#resendinvitation) for a lost email. If the person already has a disabled account, re-enable
it with [`setStatus`](#setstatus) instead.

```ts
const invitation = await iam.api.identities.invite(credential, {
  tenantId,
  email: 'alice@example.com',
  name: 'Alice Chen',
  roleIds: [editorRoleId],
  groupIds: [designGroupId],
});
// invitation.expiresAt: when the link stops working
```

## list

Lists the tenant's people and service accounts, with filters and paging.

- **Permission:** `iam:identities:read` on the tenant.
- **Audited as:** `iam:identities:read`.
- **Errors:** `INVALID_INPUT` for an unknown `kind` or `status`, or a `limit` outside 1 to 1,000.

Results are ordered by name, then ID. `kind` (`user` or `service`) and `status` (`active`, `disabled`, `deleted`)
narrow the list; tombstones are left out unless you pass `includeDeleted` or ask for `status: 'deleted'`. `query`
matches the name or email case-insensitively. `expiresBefore` keeps identities whose scheduled deactivation is at
or before that time, including ones already past it. `limit` and `offset` page through the result.

```ts
// Active accounts that end within the next 14 days.
const ending = await iam.api.identities.list(credential, {
  tenantId,
  status: 'active',
  expiresBefore: Date.now() + 14 * 86_400_000,
});
```

## listBindings

Lists an identity's role bindings, direct and through its groups, with their activation and window state.

- **Permission:** `iam:bindings:read` on the identity.
- **Audited as:** `iam:bindings:read`.
- **Errors:** `NOT_FOUND` when the identity is not in this tenant.

Each entry is the binding with its `role` and `via` (`'identity'`, or `{ groupId }` for a group binding).
[Eligible bindings](/docs/guides/privileged-access/elevation) carry `activation` while activated and
`pendingActivation` while a request awaits approval, and bindings with an access window carry `inWindow`.
Future-dated bindings are listed with their start; expired bindings and lapsed memberships are left out. The list
shows what is bound, not a decision: to see why a specific action is allowed, use
[access paths](/docs/guides/governance/access-paths).

## listGroups

Lists the groups an identity currently belongs to, with `membershipExpiresAt` on temporary memberships.

- **Permission:** `iam:groups:read` on the identity.
- **Audited as:** `iam:groups:read`.
- **Errors:** `NOT_FOUND` when the identity is not in this tenant.

Lapsed memberships are left out even before the purge job removes them, so the list matches the groups that
currently give the identity roles.

## listInvitations

Lists every member invitation of the tenant, pending or not, without tokens.

- **Permission:** `iam:identities:read` on the tenant.
- **Audited as:** `iam:identities:read`.

Each invitation shows the email, suggested name, roles, groups, the inviter, the grant authority its roles will be
issued under (present only when it carries roles or groups), when it was created and expires, and whether it was
`consumed` or `revoked`. An invitation past `expiresAt` that is neither has simply expired;
[`resendInvitation`](#resendinvitation) renews it.

## listReports

Lists the active people whose manager is this identity, by name.

- **Permission:** `iam:identities:read` on the identity.
- **Audited as:** `iam:identities:read`.
- **Errors:** `NOT_FOUND` when the identity is not in this tenant.

Disabled and deleted reports are left out. Managers are set with `managerId` on [`create`](#create) or
[`update`](#update), and they can approve requests for eligible bindings and access packages that ask for manager
approval (see [approver groups and managers](/docs/guides/privileged-access/elevation#approver-groups-and-managers)).

## listSessions

Lists an identity's unexpired sessions and API keys, most recently used first, without token hashes.

- **Permission:** `iam:identities:read` on the identity.
- **Audited as:** `iam:identities:read`.
- **Errors:** `NOT_FOUND` when the identity is not in this tenant.

Use it for device lists and support. Each session shows when it was created, last used, and expires, how it was
established (`method`), whether it completed MFA, the client details recorded at sign-in, and `impersonatorId` for
"view as" sessions. End them with [`revokeSessions`](#revokesessions).

## offboard

Disables an identity and removes everything that gave it access in one transaction, handing what it owned to a
successor.

- **Permission:** `iam:identities:update` on the identity, with recent authentication. Offboarding an owner also
  requires you to be an owner of this tenant, signed in to it with your own account, or root. Direct bindings and
  group memberships are removed as `bindings.delete` and `groups.removeMember` would, under your grant authority.
- **Audited as:** `iam:identities:update` and `identity:offboard` (with the reason, kind, successor, and every
  count).
- **Errors:** `INVALID_INPUT` for yourself, a missing reason, or a successor who is the same identity or not
  active; `ACCESS_DENIED` for a root administrator unless you are root, for an owner unless you are an owner or
  root, or for a binding or group membership issued under another administrator's grant authority; `LAST_OWNER` or
  `LAST_ROOT_ADMIN`; `NOT_FOUND` for an unknown or deleted identity or successor; `RECENT_AUTH_REQUIRED`.

In order, it removes ownership (the protected Owner binding); ends role activations; revokes
[access-package](/docs/guides/privileged-access/access-packages) assignments with the bindings and memberships
they created; deletes the remaining direct bindings and group memberships; deletes relationships; cancels pending
access and package requests; revokes the grant authorities the identity holds, so grants it issued as a delegated
administrator stop applying; moves its reports to the successor; transfers the managed resources it owns to the
successor; ends every session and API key; and disables it. Without a successor, reports are left without a
manager and owned resources are only counted (`resourcesOwned`). The result counts each step, which makes a good
record for auditors.

The identity stays as a disabled record so the audit trail still names who they were; remove it later with
[`delete`](#delete). Package rules owned by the leaver are suspended when their authority is revoked, so hand them
over first. See [offboarding](/docs/guides/privileged-access/lifecycle#offboarding).

```ts
const summary = await iam.api.identities.offboard(credential, {
  tenantId,
  identityId: leaverId,
  reason: 'Left the company (HR-1234)',
  successorId: managerId,
});
// summary.bindings, summary.memberships, summary.resourcesReassigned, ...
```

## requestPasswordReset

Emails a member a password-reset link on an administrator's behalf.

- **Permission:** `iam:identities:update` on the member, with recent authentication. For an owner you must be
  another owner of the same tenant or root; for a root administrator, root.
- **Audited as:** `iam:identities:update` and `identity:password-reset`.
- **Errors:** `FEATURE_DISABLED` when email delivery or password sign-in is not configured; `INVALID_INPUT` for a
  service account, a disabled identity, or one without an email; `ACCESS_DENIED` for an owner or root
  administrator you may not control; `RECENT_AUTH_REQUIRED`.

Unlike the public `auth.requestPasswordReset`, it works whether or not the address is verified, which makes it the
way to onboard someone created without a password. It returns `{ queued: true, email }`; the reset token goes only
to the member's inbox. Whoever controls a password reset controls the account, so the owner and root rules keep
`iam:identities:update` alone from taking over a more powerful account. See
[recovery](/docs/guides/authentication/recovery#resetting-on-someones-behalf).

## resendInvitation

Sends a member invitation again with a new token and a fresh lifetime; the earlier link stops working.

- **Permission:** `iam:identities:update` on the invitation.
- **Audited as:** `iam:identities:update`.
- **Errors:** `CONFLICT` when the invitation was already accepted or revoked; `DELIVERY_REQUIRED` without an email
  delivery callback; `NOT_FOUND` when the invitation is not in this tenant.

Use it when the first email expired, was lost, or went to spam: expired invitations can be resent. The new email
names you as the inviter, while the invitation keeps its original inviter, roles, groups, and grant authority.

## revokeInvitation

Cancels a member invitation so its link can no longer be used.

- **Permission:** `iam:identities:update` on the invitation.
- **Audited as:** `iam:identities:update`.
- **Errors:** `CONFLICT` when the invitation was already accepted or revoked; `NOT_FOUND` when it is not in this
  tenant.

The invitation stays in [`listInvitations`](#listinvitations) with `revoked: true`, and a revoked invitation cannot
be re-sent.

## revokeSessions

Ends every session and API key of an identity without disabling it.

- **Permission:** `iam:identities:update` on the identity, with recent authentication.
- **Audited as:** `iam:identities:update` and `identity:revoke-sessions` (with the number revoked).
- **Errors:** `ACCESS_DENIED` for a root administrator unless you are root; `NOT_FOUND` when the identity is not in
  this tenant; `RECENT_AUTH_REQUIRED`.

Use it for incident response or a lost device. Remembered devices and pending sign-in challenges are cleared too,
so the next sign-in needs the second factor again, and role sessions assumed from the identity and "view as"
sessions opened through its sessions end as well. The account and its access stay, so a person can sign in again
at once. For a service account this deletes its API keys; issue new ones with
[`credentials.create`](/docs/reference/api/credentials#create). The result's `revoked` is the number of session
records the identity held.

Pass `keepApiKeys: true` to end everything except the API keys: user sessions, role sessions the identity assumed in
other tenants, session tokens (including those minted from its keys), remembered devices, and pending challenges end,
while the keys keep working. Use it when a service account's session tokens may have leaked but its keys have not.
The audit event records `keptApiKeys`. A value other than `true` or `false` is `INVALID_INPUT`.

## setBoundary

Sets a root-controlled permissions boundary on one identity, capping what it may do in the tenant whatever its
roles grant.

- **Permission:** `iam:boundaries:update` on the identity, and you must be a root administrator.
- **Audited as:** `iam:boundaries:update`.
- **Errors:** `ACCESS_DENIED` for anyone but root; `INVALID_POLICY`, `INVALID_ACTION`, or `INVALID_RESOURCE_TYPE`
  for a document the catalog rejects; `NOT_FOUND` when the identity is not in this tenant; `INVARIANT_VIOLATION`
  when the change would break an enforced access invariant.

A <Term id="boundary">boundary</Term> never grants: an action is allowed only when a role grants it and the
boundary allows it too, and boundaries set on the tenant and its ancestors apply on top. Each identity has at most
one boundary per tenant, and calling again replaces it. Boundaries are platform controls, which is why tenant
administrators cannot set them. See [boundaries](/docs/guides/authorization/policies#boundaries).

```ts
// A vendor account may never reach beyond support tickets, whatever roles it is given.
await iam.api.identities.setBoundary(rootCredential, {
  tenantId,
  identityId: vendorId,
  document: {
    version: 1,
    statements: [{ effect: 'allow', actions: ['tickets:*'], resources: ['*'] }],
  },
});
```

## setOwner

Makes a member an owner of the tenant, or removes their ownership.

- **Permission:** `iam:identities:update` on the member, with recent authentication, and you must be an owner of
  this tenant yourself (signed in to it with your own account, not through an assumed role) or root.
- **Audited as:** `iam:identities:update`.
- **Errors:** `ACCESS_DENIED` when you are not an owner or root; `INVALID_INPUT` for a service account, a disabled
  member, or a non-boolean `owner`; `LAST_OWNER` when removing the last active owner; `RECENT_AUTH_REQUIRED`.

Ownership is the protected [Owner role](/docs/guides/authorization/roles#the-owner-role), which allows every action
in the tenant and cannot be bound, edited, or requested any other way. Granting it binds the Owner role under a new,
unrestricted grant authority delegated from the one you grant under, so the new owner can administer and delegate
like you, within your authority chain; if an authority above theirs is revoked (offboarding or deleting you
revokes yours), their grants stop applying. Removing ownership deletes the Owner binding but leaves the person's
grant authorities, so grants they issued keep applying; revoke those with
[`authorities.revoke`](/docs/reference/api/authorities#revoke) if they should not.

## setStatus

Disables an identity or re-enables it.

- **Permission:** `iam:identities:update` on the identity, with recent authentication.
- **Audited as:** `iam:identities:update`.
- **Errors:** `INVALID_INPUT` for a status other than `active` or `disabled`; `ACCESS_DENIED` for a root
  administrator unless you are root; `LAST_OWNER` or `LAST_ROOT_ADMIN` when disabling the last active owner or
  root administrator; `INVALID_TRANSITION` (409) when re-enabling an identity whose `expiresAt` has passed;
  `NOT_FOUND` for a deleted identity; `INVARIANT_VIOLATION` when the change would break an enforced access
  invariant.

Disabling ends every session and API key at once, and the identity can no longer sign in or authenticate. Its
roles, groups, and attributes are kept and apply again when you re-enable it, but ended sessions and keys do not
come back. It works for people and service accounts alike
([`serviceAccounts.setStatus`](/docs/reference/api/service-accounts#setstatus) is the service-account
equivalent). Access-package rules are reconciled after the change and never assign anything to a disabled
identity. To remove access for good, use [`offboard`](#offboard).

## unlock

Clears the rate-limit counters that lock a person out of sign-in, recovery, and MFA after too many attempts.

- **Permission:** `iam:identities:update` on the identity, with recent authentication.
- **Audited as:** `iam:identities:update` and `identity:unlock` (with `supported` and `cleared`).
- **Errors:** `RECENT_AUTH_REQUIRED`; `NOT_FOUND` for an unknown or deleted identity.

It resets the counters kept for the identity's email, phone, and ID across sign-in, sign-up, re-authentication,
email verification and change, phone verification, password reset and change, passwordless, passkey, and
second-factor flows. Counters kept per client address and
[network blocks](/docs/reference/api/security#unblocknetwork) are not affected. A custom limiter without a `reset`
method returns `{ supported: false, cleared: 0 }`; otherwise `cleared` is the number of counters reset. See
[lockouts](/docs/guides/authentication/recovery#lockouts).

## update

Changes an identity's name, declared attributes, email, manager, or scheduled deactivation.

- **Permission:** `iam:identities:update` on the identity. An email change also needs recent authentication, and
  for an owner or root administrator the same control as [`requestPasswordReset`](#requestpasswordreset); changing
  a root administrator's expiry needs root.
- **Audited as:** `iam:identities:update`, plus `identity:email-change` (with the old and new address) when the
  email changes.
- **Errors:** `INVALID_INPUT` when no field is given, for an undeclared or mistyped attribute, an `expiresAt` that
  is not in the future or is more than ten years ahead, an email on a service account, or a manager who is the
  identity itself, is not active, or reports to the identity (directly or further down); `IDENTITY_EXISTS` when the
  new email is taken in this tenant; `LAST_OWNER` when setting an expiry on the last active owner;
  `ACCESS_DENIED` for a protected account you may not change; `NOT_FOUND` for a deleted identity;
  `INVARIANT_VIOLATION` when the change would break an enforced access invariant.

Only the fields you pass change. `attributes` replaces the whole set of declared attributes, validated against
`permissions.identityAttributes`. A new email is marked unverified and every session ends, because whoever
controls the sign-in address controls the account. `expiresAt: null` clears a scheduled deactivation and
`managerId: null` removes the manager; to end access immediately, disable the identity instead of setting an
expiry. After the change, automatic access-package rules are reconciled for the identity, so new attribute values
can change which packages it receives.

```ts
await iam.api.identities.update(credential, {
  tenantId,
  identityId,
  attributes: { department: 'finance', level: 3 },
  managerId: newManagerId,
  expiresAt: null, // no longer a temporary account
});
```
