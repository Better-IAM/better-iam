# agreements

Agreements are versioned terms of use that a tenant asks its members to accept: an acceptable-use policy, an NDA,
data-handling rules. Better IAM records who accepted which version and when, and exposes the result to policies, so
you can hold back access until people accept. See the [terms of use guide](/docs/guides/governance/agreements).

## Versions, lapses, and enforcement

An agreement starts at version 1. Editing it with `newVersion: true` publishes the next version, and everyone must
accept again; an edit without it (a typo fix, a new link) keeps existing acceptances valid. An acceptance counts only
while it is for the current version and, when the agreement sets `reacceptAfterDays`, is younger than that many days
(annual re-acceptance, for example). Each person has one acceptance record per agreement, replaced each time they
accept.

Enforcement is an ordinary policy decision. Every evaluation for a person in their own tenant carries two
[condition](/docs/guides/authorization/conditions) keys:

- `principal.agreements`: the names of the agreements the person has accepted in their current version.
- `principal.pendingAgreements`: how many `required` agreements they still owe. Service accounts cannot accept
  anything, so nothing is pending for them.

A deny statement on the count holds back access until every required agreement is accepted:

```json
{
  "effect": "deny",
  "actions": ["documents:*"],
  "resources": ["*"],
  "conditions": { "NumericGreaterThan": { "principal.pendingAgreements": 0 } }
}
```

`{ "ArrayContains": { "principal.agreements": ["Beta program"] } }` grants something only to people who accepted an
optional agreement. Sessions of an assumed role carry neither key, so conditions on them do not match there.
[`accessPaths.find`](/docs/reference/api/access-paths#find) tells a denied person when accepting their pending
agreements would let them in.

## accept

Records that you accept the given version of an agreement.

- **Permission:** None beyond an ordinary session of the agreement's tenant.
- **Audited as:** `agreement:accept`, with the agreement's name and version.
- **Errors:** `VERSION_CONFLICT` (409) when `version` is not the current version; `IMPERSONATION_RESTRICTED` from an
  impersonation session; `INVALID_INPUT` for a service account; `ACCESS_DENIED` from a role session or another
  tenant's session; `NOT_FOUND` when the agreement is not in this tenant.

Pass the `version` you showed the person, from `listMine`. If the agreement changed in the meantime the call fails,
so nobody accepts text they were not shown. Accepting again restarts the `reacceptAfterDays` clock. The acceptance
applies from the next authorization check; enforced invariants do not guard it.

```ts
const mine = await iam.api.agreements.listMine(credential, { tenantId });
const owed = mine.filter((agreement) => agreement.required && !agreement.accepted);
for (const agreement of owed)
  await iam.api.agreements.accept(credential, { tenantId, agreementId: agreement.id, version: agreement.version });
```

## create

Publishes a new agreement at version 1, required by default.

- **Permission:** `iam:agreements:manage` on the tenant.
- **Audited as:** `iam:agreements:manage`.
- **Errors:** `CONFLICT` when an agreement with the same name (ignoring case) exists; `LIMIT_EXCEEDED` (409) when
  the tenant already has 50; `INVALID_INPUT` for an empty name or one over 100 characters, empty content or content
  over 50 000 characters or with control characters other than tabs and line breaks, a `url` that is not http(s), or
  a `reacceptAfterDays` outside 1 to 3650; `INVARIANT_VIOLATION` when a new required agreement would make a policy
  deny someone an enforced invariant says must be allowed.

`content` is the text people accept (plain text or Markdown); `url` optionally links to the canonical document.
`required: false` makes it optional: it never counts toward `principal.pendingAgreements`, and people who accept it
appear in `principal.agreements`. Publishing a required agreement raises every person's
`principal.pendingAgreements` at once: if a policy already denies on that count, people lose the access it covers
until they accept.

```ts
await iam.api.agreements.create(credential, {
  tenantId,
  name: 'Acceptable use',
  content: 'Use company systems for work. Report incidents within 24 hours.',
  url: 'https://intranet.example.com/policies/acceptable-use',
  reacceptAfterDays: 365,
});
```

## delete

Deletes an agreement together with every acceptance of it.

- **Permission:** `iam:agreements:manage` on the agreement.
- **Audited as:** `iam:agreements:manage`.
- **Errors:** `NOT_FOUND` when the agreement is not in this tenant; `INVARIANT_VIOLATION` when the change would break
  an enforced invariant.

Its name disappears from `principal.agreements` and, if it was required, it stops counting toward
`principal.pendingAgreements`. The acceptance history is gone with it; the audit log keeps the `agreement:accept`
events.

## list

Lists the tenant's agreements by name, with their full text, version, and settings.

- **Permission:** `iam:agreements:read` on the tenant.
- **Audited as:** `iam:agreements:read`.

## listMine

Returns every agreement of the tenant with the text and whether you have accepted its current version.

- **Permission:** None beyond an ordinary session of the tenant.
- **Audited as:** Not audited; it only reads.
- **Errors:** `ACCESS_DENIED` from a role session or another tenant's session.

Agreements you still owe come first, required ones before optional ones. Each entry carries `accepted` plus, when you
accepted some version, `acceptedAt` and `acceptedVersion`, so you can tell "never accepted" from "accepted an older
version". Use it to render a banner or an acceptance screen; `useAgreements` does this in React and Vue apps.

## status

Reports who accepted an agreement's current version and which active people still owe it.

- **Permission:** `iam:agreements:read` on the agreement.
- **Audited as:** `iam:agreements:read`.
- **Errors:** `NOT_FOUND` when the agreement is not in this tenant.

`accepted` lists people with a current acceptance (version and time). `pending` lists every other active person,
with `acceptedVersion` when they accepted an older version or their acceptance lapsed. Only people are reported, not
service accounts. Use it to chase stragglers before you turn on a policy that denies on
`principal.pendingAgreements`.

## update

Edits an agreement, optionally publishing the change as a new version that everyone must accept again.

- **Permission:** `iam:agreements:manage` on the agreement.
- **Audited as:** `iam:agreements:manage`.
- **Errors:** `NOT_FOUND` when the agreement is not in this tenant; `CONFLICT` for a name another agreement uses;
  `INVALID_INPUT` for the same validation as `create`; `INVARIANT_VIOLATION` when the change would break an enforced
  invariant.

Fields you omit keep their values. `newVersion: true` increments the version, so every existing acceptance stops
counting; without it acceptances stay valid even if you change the text. `reacceptAfterDays: null` removes the lapse,
and an empty `url` removes the link. A new `reacceptAfterDays` applies to existing acceptances at once, measured from
when each was given. Policies match `principal.agreements` by name, so renaming an agreement changes which
statements match it.

```ts
// Material change: everyone accepts again.
await iam.api.agreements.update(credential, {
  tenantId,
  agreementId,
  content: 'Use company systems for work. Report incidents within 4 hours.',
  newVersion: true,
});
```
