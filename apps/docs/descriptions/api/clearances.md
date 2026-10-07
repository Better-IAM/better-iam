# clearances

Security clearances and mandatory access control: classification schemes, adjudicated clearances, and labels that
every decision enforces. A tenant defines a scheme of ranked levels, compartments, and dissemination controls (NOFORN
and REL TO); officers grant people, service accounts, and agents a clearance and read them into compartments; and
resources carry IAM-held labels. At decision time every party of the session must dominate a resource's label, or the
decision is refused (`CLEARANCE_REQUIRED`, shown to callers as `ACCESS_DENIED`) before any role or policy is read:
the Bell-LaPadula "no read up" rule. The group needs the deployment's `clearances` option and answers
`FEATURE_DISABLED` (403) for every method without it. The guide is
[Security clearances](/docs/guides/security-clearances).

## Schemes, clearances, and labels

The scheme in force for a tenant is the one defined closest to the root of its ancestry, so an organization's scheme
applies to all its projects and a platform scheme to every tenant. A scheme has 2 to 20 levels with ranks from 0, up
to 200 compartments with opaque ids (names can be sensitive, so audit events and emails only ever carry ids), owner
countries (alpha-3), and the caveats labels may use. Its settings say which resource types must carry a label
(`requireLabels`, `*` for every application type), an optional `defaultLabel` for those, the level guests count at
most (`guestCeiling`), whether interim clearances count, and the adjudication mode.

A clearance (one per identity, in the identity's tenant) counts at decision time only while the identity is active,
the record was issued under the scheme in force, its status is `active` (or `interim` where the scheme allows it), and
it has not reached `expiresAt`. A read-in counts while its NDA acceptance (when it names an
[agreement](/docs/reference/api/agreements)) is current. Citizenship comes only from the adjudicated record, never
from identity attributes.

A label is `{ level, compartments?, noforn?, releasableTo? }`. The label a decision applies joins the resource's own
IAM label, the labels its managed ancestors pass down (`inheritToChildren`, 16 levels at most), and the
`classification` your `resolveResource` returns, which can therefore only raise it. Labels outlive their resources.
`iam:*` actions are never subject to labels, so administration always works.

## Who may call what

Officers hold `iam:clearances:adjudicate` (and `iam:clearances:suspend` for incidents) on `iam/clearances/{identityId}`;
security administrators `iam:classifications:manage` on `iam/classifications/scheme`, and `iam:classifications:label`
or `iam:classifications:declassify` on `iam/classifications/labels/{type}/{id}`; reviewers `iam:clearances:read`.
Changes that widen access (`defineScheme`, `updateScheme`, `grant`, `update`, `readIn`, `reinstate`, `revoke`,
`declassify`) also need a recent sign-in; `suspend` and `debrief` do not. Nobody adjudicates their own clearance,
owners and root included, nor that of anyone acting in their session (an agent cannot adjudicate its sponsor). Guests
never adjudicate, and nothing that changes clearances or labels works while impersonating
(`IMPERSONATION_RESTRICTED`).

Under `within-own` adjudication (the default) an officer grants, updates to, and reinstates only levels their own
clearance holds, and reads people only into compartments they are read into themselves. While nobody in the scheme's
subtree holds an active clearance at a level (or is read into a compartment), an owner of the tenant in their own
session or a root administrator may grant it anyway: a bootstrap, audited with `bootstrap: true`. `unrestricted`
adjudication drops the rule.

## templates

Lists the built-in schemes a tenant can start from: `us`, `uk`, `nato`, and `corporate`.

- **Permission:** None beyond a valid credential.
- **Audited as:** Not audited.
- **Errors:** `FEATURE_DISABLED` (403) without the `clearances` option; `UNAUTHENTICATED`.

Each entry is `{ id, name, definition }`. Compartments are always empty: add your own after defining the scheme. The
same definitions are exported as `classificationTemplates` from `better-iam/core`.

## getScheme

Returns the classification scheme in force for a tenant and where it is defined, or null.

- **Permission:** `iam:clearances:read` on `iam/classifications/scheme`.
- **Audited as:** `iam:clearances:read`.

`tenantId` in the result is the defining tenant, and `inherited` is true when an ancestor defines it (change it there).
The result carries the definition with compartment names, the settings, and the `version` that
[`updateScheme`](#updatescheme) takes.

## defineScheme

Defines the tenant's classification scheme from a template or a definition of your own.

- **Permission:** `iam:classifications:manage` on `iam/classifications/scheme`, and a recent sign-in.
- **Audited as:** `iam:classifications:manage`, plus `classification:scheme-define` with the template, level and
  compartment ids, and the settings.
- **Errors:** `CONFLICT` (409) when the tenant, an ancestor, or a tenant below it already defines one;
  `INVALID_INPUT` without exactly one of `template` and `definition`, for an unknown template, a definition that does
  not validate (levels, ranks, ids, names, compartments, countries, caveats, NOFORN without an owner country), a
  missing `name` or one over 100 characters, more than 100 `requireLabels` or a platform type among them, a
  `defaultLabel` invalid for the definition, a `guestCeiling` that is not a level, an unknown `adjudication`, or more
  than 20 `notify.emails`; `RECENT_AUTH_REQUIRED`.

Settings default to no required labels, no default label, no guest clearances (`guestCeiling: null`), no interim
clearances, and `within-own` adjudication. Decisions in the tenant and every tenant below it apply the scheme from the
next request.

```ts
await iam.api.clearances.defineScheme(credential, {
  tenantId,
  name: 'Acme classification',
  template: 'us',
  requireLabels: ['document'],
  guestCeiling: 'C',
  interimAllowed: true,
});
```

## updateScheme

Changes the scheme the tenant defines: its settings, or its definition within rules that keep what is in use.

- **Permission:** `iam:classifications:manage` on `iam/classifications/scheme`, and a recent sign-in.
- **Audited as:** `iam:classifications:manage`, plus `classification:scheme-update` with the changed field names, the
  new version and, for a new definition, the level, compartment, and owner country ids.
- **Errors:** `NOT_FOUND` when no scheme applies; `CONFLICT` (409) when an ancestor defines the scheme in force;
  `VERSION_CONFLICT` (409) when `version` is not the stored one; `RESOURCE_IN_USE` (409) when the new definition
  re-ranks any level (labels your resolver asserts or a `defaultLabel` may use any level, so none is ever re-ranked,
  and one removed earlier comes back only at the rank it had), removes a level that a live clearance or a label uses,
  removes a compartment in use, or would make a label invalid; `INVALID_INPUT` for a `template`, new levels that do not
  rank above every kept level, a definition or setting that does not validate, or a kept `defaultLabel` the new
  definition cannot read; `RECENT_AUTH_REQUIRED`.

Only the fields you pass change; `null` clears `defaultLabel` and `notify`. Settings such as `requireLabels`,
`guestCeiling`, and `interimAllowed` take effect on the next decision. Adding an owner country widens who reads NOFORN
material.

```ts
const scheme = (await iam.api.clearances.getScheme(credential, { tenantId }))!;
await iam.api.clearances.updateScheme(credential, {
  tenantId,
  version: scheme.version,
  definition: { ...scheme.definition, compartments: [{ id: 'LANTERN', name: 'Project Lantern' }] },
});
```

## grant

Grants an identity a clearance under the scheme in force: a level, adjudicated citizenship, and optional dates.

- **Permission:** `iam:clearances:adjudicate` on `iam/clearances/{identityId}`, and a recent sign-in.
- **Audited as:** `iam:clearances:adjudicate`, plus `clearance:grant` with the level, status, end, and `bootstrap`.
- **Errors:** `CONFLICT` (409) when the identity already holds a live (interim, active, or suspended) clearance;
  `ACCESS_DENIED` for your own clearance or that of a party of your session, for a guest officer, and under
  `within-own` for a level beyond your own clearance (all audited); `INVALID_INPUT` for an identity that is not active,
  an unknown level, a guest above the scheme's guest ceiling (or under a scheme without one), `interim` where the
  scheme does not allow it, more than 10 or malformed `citizenship` codes, a malformed `investigation`, an `expiresAt`
  that is not in the future, or dates more than twenty years ahead; `NOT_FOUND` when no scheme applies or the identity
  is not in this tenant; `IMPERSONATION_RESTRICTED`; `RECENT_AUTH_REQUIRED`.

People, service accounts, and agents can hold clearances; an agent's key reads a label only when the agent and its
sponsor both dominate it. A revoked or terminated record is replaced by a new grant (the audit trail keeps the
history). The person learns nothing by email; their access changes from the next request.

```ts
await iam.api.clearances.grant(credential, {
  tenantId,
  identityId: alice.id,
  level: 'S',
  citizenship: ['USA'],
  investigation: { kind: 'T5', completedAt: Date.parse('2026-08-01') },
  reinvestigationDue: Date.parse('2031-08-01'),
});
```

## update

Changes a live clearance's level, citizenship, interim status, investigation, or dates.

- **Permission:** `iam:clearances:adjudicate` on `iam/clearances/{identityId}`, and a recent sign-in.
- **Audited as:** `iam:clearances:adjudicate`, plus `clearance:update` with the level, the previous level, the status,
  and the changed fields (none when nothing changed).
- **Errors:** `NOT_FOUND` when the identity holds no live clearance; `CONFLICT` (409) for a clearance issued under
  another scheme (revoke it and grant a new one); `ACCESS_DENIED` as for [`grant`](#grant), applied to the higher of
  the old and the new level; `INVALID_INPUT` as for `grant`, or when the clearance's level left the scheme and no new
  `level` is given; `IMPERSONATION_RESTRICTED`; `RECENT_AUTH_REQUIRED`.

`null` clears `investigation`, `reinvestigationDue`, and `expiresAt`. `interim: false` makes an interim clearance final.
Changing a suspended clearance keeps it suspended (an interim change applies when it is reinstated).

## readIn

Reads a person into a compartment of the scheme, optionally backed by a non-disclosure agreement.

- **Permission:** `iam:clearances:adjudicate` on `iam/clearances/{identityId}`, and a recent sign-in.
- **Audited as:** `iam:clearances:adjudicate`, plus `clearance:read-in` with the compartment id, the level, the
  agreement, and `bootstrap`.
- **Errors:** `CONFLICT` (409) when already read in, or for a clearance issued under another scheme;
  `INVALID_TRANSITION` (409) for a suspended clearance; `INVALID_INPUT` for a compartment the scheme does not define or
  a guest; `NOT_FOUND` when the identity holds no live clearance or the agreement is not in the person's tenant;
  `ACCESS_DENIED` for your own clearance and, under `within-own`, for a compartment you are not read into;
  `IMPERSONATION_RESTRICTED`; `RECENT_AUTH_REQUIRED`.

With `agreementId`, the read-in counts only while the person's acceptance of the agreement's current version is
current: a new version, a lapsed `reacceptAfterDays`, or deleting the agreement closes it until they accept again.
The person may accept after the read-in; `acceptedAt` records an acceptance that was current at the time.

```ts
await iam.api.clearances.readIn(credential, {
  tenantId,
  identityId: alice.id,
  compartmentId: 'LANTERN',
  agreementId: lanternNdaId,
});
```

## debrief

Ends one read-in.

- **Permission:** `iam:clearances:adjudicate` on `iam/clearances/{identityId}`.
- **Audited as:** `iam:clearances:adjudicate`, plus `clearance:debrief` with the compartment id and the reason.
- **Errors:** `NOT_FOUND` when the person is not read into the compartment or is not in this tenant; `ACCESS_DENIED`
  for a guest officer; `INVALID_INPUT` for a `reason` over 512 characters; `IMPERSONATION_RESTRICTED`.

Debriefing only takes access away, so it needs no recent sign-in, works on your own clearance and on a suspended one,
and is never blocked by an "expect allow" access invariant.

## suspend

Takes a clearance out of force at once, for an incident or an investigation.

- **Permission:** `iam:clearances:suspend` on `iam/clearances/{identityId}`; no recent sign-in.
- **Audited as:** `iam:clearances:suspend`, plus `clearance:suspend` with the level, the reason, and the incident.
- **Errors:** `NOT_FOUND` when the identity holds no interim or active clearance; `INVALID_TRANSITION` (409) when it is
  already suspended; `INVALID_INPUT` without a `reason` (up to 512 characters); `ACCESS_DENIED` for a guest officer;
  `IMPERSONATION_RESTRICTED`.

Every decision from the next request treats the person as uncleared. Pass the incident's id as `incidentId`. The person
gets a `clearance-status` email unless `notifyPerson: false` (an investigation that must not tip them off). Only
[`reinstate`](#reinstate) lifts a suspension.

```ts
await iam.api.clearances.suspend(credential, {
  tenantId,
  identityId: bob.id,
  reason: 'Under investigation',
  incidentId,
  notifyPerson: false,
});
```

## reinstate

Lifts a suspension, back to the active or interim status the clearance had.

- **Permission:** `iam:clearances:adjudicate` on `iam/clearances/{identityId}`, and a recent sign-in.
- **Audited as:** `iam:clearances:adjudicate`, plus `clearance:reinstate` with the level, status, reason, and
  `bootstrap`.
- **Errors:** `INVALID_TRANSITION` (409) when the clearance is not suspended; `NOT_FOUND` when the identity holds no
  live clearance; `CONFLICT` (409) for a clearance issued under another scheme; `INVALID_INPUT` when its level left the
  scheme; `ACCESS_DENIED` for your own clearance and, under `within-own`, unless your clearance holds its level and every
  compartment it is read into (they come back with it); `IMPERSONATION_RESTRICTED`; `RECENT_AUTH_REQUIRED`.

The person gets a `clearance-status` email.

## revoke

Revokes a clearance for cause and debriefs every compartment.

- **Permission:** `iam:clearances:adjudicate` on `iam/clearances/{identityId}`, and a recent sign-in.
- **Audited as:** `iam:clearances:adjudicate`, plus `clearance:revoke` with the level, the reason, and the debriefed
  compartment ids.
- **Errors:** `NOT_FOUND` when the identity holds no live clearance; `INVALID_INPUT` without a `reason` (up to 512
  characters); `ACCESS_DENIED` for a guest officer; `IMPERSONATION_RESTRICTED`; `RECENT_AUTH_REQUIRED`.

The record stays as history with status `revoked`, through offboarding and deletion too; a new clearance needs a new
[`grant`](#grant). The person gets a `clearance-status` email unless `notifyPerson: false`. Revoking is never blocked by
an "expect allow" access invariant.

## get

Returns one identity's clearance as officers see it, or null.

- **Permission:** `iam:clearances:read` on `iam/clearances/{identityId}`.
- **Audited as:** `iam:clearances:read`.
- **Errors:** `NOT_FOUND` when the identity is not in this tenant.

Besides the stored record, the view reports `effectiveStatus` and `effectiveLevel` (what decisions count right now:
`none`, `expired`, a guest's capped level), compartment names, and whether each read-in is `current`.

## list

Lists the tenant's clearances by person name, optionally by status, level, or end.

- **Permission:** `iam:clearances:read` on `iam/clearances`.
- **Audited as:** `iam:clearances:read`.
- **Errors:** `INVALID_INPUT` for an unknown `status`, an `expiringWithinDays` outside 1 to 3650, a `limit` outside 1
  to 500, or an `offset` outside 0 to 1000000.

`status` filters by the stored status, `level` by level id, and `expiringWithinDays` keeps clearances whose
`expiresAt` falls within that many days (ended ones included). `total` counts every match before paging with `limit`
(100 by default) and `offset`.

## mine

Returns the caller's own clearance under the scheme in force, with the scheme's levels.

- **Permission:** None beyond the caller's own session or API key in the tenant.
- **Audited as:** Not audited; it only reads.
- **Errors:** `ACCESS_DENIED` from a role session, session token, delegated session, or a session of another tenant;
  `IMPERSONATION_RESTRICTED` while impersonating.

The result is `{ scheme, clearance }`: the scheme's name and levels (null when no scheme applies), and the caller's
level, status, effective status, citizenship, dates, and read-ins with `current: false` for those whose NDA still needs
accepting (null when they hold no clearance). It backs a "my clearance" page.

## explain

Tells an officer whether a person may read a resource and, if not, which dimension of the label they fail.

- **Permission:** `iam:clearances:adjudicate` on `iam/clearances/{identityId}`.
- **Audited as:** `iam:clearances:adjudicate`.
- **Errors:** `NOT_FOUND` when no scheme applies or the identity is not in this tenant.

Decisions only ever say `CLEARANCE_REQUIRED`, and audit events only `{ mandatory: 'clearance' }`. `explain` is the one
place that names the failure: `level`, `compartment`, `noforn`, `releasability`, or `invalid-label` (also for a
missing required label), with the label decisions apply (after inheritance, the resolver, and the default) and the
clearance of every party of the person's own sessions (an agent with its sponsor). It works for resources that no
longer exist, since their labels remain.

```ts
const why = await iam.api.clearances.explain(credential, {
  tenantId,
  identityId: alice.id,
  type: 'document',
  id: 'q3-plan',
});
// { allowed: false, failure: 'compartment', label: { level: 'S', compartments: ['LANTERN'] }, party, parties }
```

## label

Labels a resource or raises its label; lowering any part of a label is a declassification.

- **Permission:** `iam:classifications:label` on `iam/classifications/labels/{type}/{id}`.
- **Audited as:** `iam:classifications:label`, plus `classification:label` with the type, level, compartment ids,
  caveats, `inheritToChildren`, and the previous level.
- **Errors:** `ACCESS_DENIED` (audited) when the new label does not cover the current one in every dimension, would
  turn inheritance off, or replaces a label written under another scheme (use [`declassify`](#declassify));
  `INVALID_INPUT` for a label the scheme cannot read (unknown level or compartment, a caveat the scheme does not use, a
  malformed country), a platform type, or a `type` that is not a resource type name (a lowercase letter, then
  lowercase letters, digits, or `-`); `NOT_FOUND` when no scheme applies; `IMPERSONATION_RESTRICTED`.

The resource need not exist yet, and the label outlives it, so deleting and recreating a resource never declassifies
it; a registered resource deleted while it inherits a label keeps that label as its own. With
`inheritToChildren: true` the label also applies to every managed descendant. Labeling the same label again changes
nothing and records no `classification:label` event.

```ts
await iam.api.clearances.label(credential, {
  tenantId,
  type: 'document',
  id: 'q3-plan',
  label: { level: 'S', compartments: ['LANTERN'], noforn: true },
});
```

## declassify

Lowers, changes, or removes a resource's label, with a reason.

- **Permission:** `iam:classifications:declassify` on `iam/classifications/labels/{type}/{id}`, and a recent sign-in.
- **Audited as:** `iam:classifications:declassify`, plus `classification:declassify` with the label before and after
  (or `removed: true`) and the reason.
- **Errors:** `ACCESS_DENIED` (audited) when your own clearance does not dominate the current label, or for a guest
  officer; `NOT_FOUND` when the resource has no label or no scheme applies; `INVALID_INPUT` without `label` (pass
  `null` to remove it) or `reason`, or for a label the scheme cannot read; `IMPERSONATION_RESTRICTED`;
  `RECENT_AUTH_REQUIRED`.

Nobody declassifies what they could not read, as the scheme in force reads the label, even one written under another
scheme. Only a label naming a level, compartment, or caveat the scheme in force does not define, which no clearance can
dominate, may be repaired by anyone with the permission. `inheritToChildren: false` stops a label passing down.

## getLabel

Returns a resource's own IAM label and what it inherits from its managed parents.

- **Permission:** `iam:clearances:read` on `iam/classifications/labels/{type}/{id}`.
- **Audited as:** `iam:clearances:read`.
- **Errors:** `NOT_FOUND` when no scheme applies; `INVALID_INPUT` for a platform type.

`label` is null when the resource has none of its own, and `inherited` is the join of the labels its managed ancestors
pass down, the labels of the same model in the tenants above, and, for an SSH login, its host's label. A label your
resolver returns is applied by decisions but is not shown here; use [`explain`](#explain) for
the label a decision applies.

## listLabels

Lists the tenant's IAM labels, optionally of one resource type or level.

- **Permission:** `iam:clearances:read` on `iam/classifications/labels`.
- **Audited as:** `iam:clearances:read`.
- **Errors:** `INVALID_INPUT` for a platform type, a `limit` outside 1 to 500, or an `offset` outside 0 to 1000000.

Labels are ordered by type and resource id; `total` counts every match before paging with `limit` (100 by default)
and `offset`. Each carries the level name when the scheme still has the level.
