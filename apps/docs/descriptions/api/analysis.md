# analysis

Access analysis scans a tenant's configuration for risky or stale access, such as administrators without MFA or
dormant accounts that still hold roles. It also reports API keys nobody uses, broken manager links, and more. It
answers "what should we fix first?" without anyone reading every policy by hand, and a policy linter catches
documents that do not do what their author intended. Nothing here changes access: findings are observations you act on through the other
groups, or suppress with a recorded reason when a risk is accepted.

## What the scan checks

[`findings`](#findings) runs every check below in one read-only transaction. "Administrator" means a tenant owner
or anyone who holds a role that grants every action (`*` or `iam:*`) on every resource without conditions.
Protected system policies and the Owner role are not reported against.

| Kind | Severity | Reported when |
| --- | --- | --- |
| `unrestricted-admin-policy` | high | A policy or a role's inline document allows every action on every resource without conditions. |
| `admin-without-mfa` | high | A human administrator has neither an authenticator app nor a passkey, and the tenant does not require MFA. |
| `separation-of-duties` | high | An active person holds roles that a [separation-of-duties rule](/docs/guides/authorization/separation-of-duties) forbids together. |
| `team-maintainers-grant-admin` | high | A [team](/docs/reference/api/teams) (or a team above it) holds an administrator role as standing access, and maintainers manage its membership, so they can make anyone an administrator. |
| `broad-action-wildcard` | medium | A policy allows a service-wide wildcard such as `documents:*` without conditions, which also grants actions added later. |
| `service-account-admin` | medium | A service account is an administrator, so a leaked API key would control the organization. |
| `dormant-access` | medium | A person holding bindings or ownership has not signed in for `dormantDays` (an account that never signed in counts from its creation). |
| `stale-api-key` | medium | An unexpired API key has not been used for `dormantDays`. |
| `trust-without-mfa` | medium | A live [trust](/docs/reference/api/trust) lets its source assume a role without MFA. |
| `standing-privileged-access` | medium | A person holds an administrator role through a direct, permanent binding that is not eligible (just-in-time). |
| `manager-cycle` | medium | A person's manager chain loops back to them. |
| `unattached-policy` | low | A policy is not attached to any role. |
| `unused-role` | low | A role is not bound to anyone and no trust uses it. |
| `empty-role` | low | A role has no inline document and no attached policies. |
| `empty-group-with-access` | low | A group holds role bindings but has no members, so anyone added later inherits them at once. |
| `unused-eligible-binding` | low | An eligible binding has existed for longer than `dormantDays` without a recorded activation. |
| `orphaned-manager` | low | A person's manager no longer exists or is not active, so manager approvals cannot reach them. |
| `policy-lint` | low | A stored policy or a role's inline document has linter warnings of severity `warning` (see [`lintPolicy`](#lintpolicy)). |
| `team-without-maintainer` | low | A team has members but no active maintainer (in it or above it), so only administrators can manage it. |
| `department-without-head` | low | A [department](/docs/reference/api/departments) has people but no active head, so manager approvals routed through the org chart stop there. |

Each finding has a title, a detail that says what to do, and the subject it concerns (a policy, role, identity,
group, trust, credential, delegation, team, or department).

## Suppressing findings

Some findings describe accepted risk: a break-glass administrator account, or a service account that must be
powerful. Suppress them with a reason so they stop cluttering the results. Finding IDs are deterministic: the same
condition on the same subject always yields the same 24-character ID, so a suppression keeps applying for as long
as the condition holds, and again if it returns later. Suppressed findings are counted in `summary.suppressed` and
listed, with who suppressed them, when, and why, when you pass `includeSuppressed: true`.

## findings

Runs every access-analysis check on the tenant and returns the findings, most severe first, with counts per
severity.

- **Permission:** `iam:analysis:read` on `iam/analysis/*`.
- **Audited as:** `iam:analysis:read`.
- **Errors:** `INVALID_INPUT` when `dormantDays` is outside 1 to 3650.

`dormantDays` (default 90) sets when an unused account, API key, or eligible binding is reported. Suppressed
findings are left out unless `includeSuppressed` is `true`. Run it on a schedule and alert on new high findings;
the `analyze` [CLI command](/docs/reference/cli#analyze) does this with `--fail-on high`, which suits a CI or cron
job.

```ts
const { summary, findings } = await iam.api.analysis.findings(credential, { tenantId, dormantDays: 60 });
for (const finding of findings.filter((item) => item.severity === 'high'))
  console.log(finding.title, finding.detail);
```

## lintPolicy

Checks a policy document, or a stored policy, for errors and for statements that likely do not do what they say.

- **Permission:** `iam:policies:read` on the policy (with `policyId`) or on the tenant (with a candidate
  `document`).
- **Audited as:** `iam:policies:read`.
- **Errors:** `INVALID_INPUT` unless exactly one of `document` and `policyId` is given; `NOT_FOUND` when the
  policy is not in this tenant.

The document is first validated the way storage would validate it, including unknown actions and resource types.
A document storage would reject is not thrown as an error: the result has `valid: false`, the `error` code and
message, and no warnings. A valid document gets `warnings`, each with a `code`, a `severity` (`warning`: probably a
mistake; `info`: worth a look, often intended), the statement index, and a message. Examples include an allow that
makes every holder a full administrator, a condition key the server never sets, a deny that silently never applies
when an optional key is missing, an allow that an unconditional deny shadows, and duplicate statements.

Use it in a policy editor before saving, or in CI over documents kept in version control. Pass `contextKeys` to
name keys your application supplies through `resolveContext`, so they are not reported as unknown. See
[policies](/docs/guides/authorization/policies) and [conditions](/docs/guides/authorization/conditions).

```ts
const result = await iam.api.analysis.lintPolicy(credential, {
  tenantId,
  document: {
    version: 1,
    statements: [{ effect: 'allow', actions: ['documents:*'], resources: ['*'] }],
  },
});
// result.valid === true; result.warnings[0].code === 'service-wildcard'
```

## suppress

Hides one finding from future results and records why.

- **Permission:** `iam:analysis:update` on `iam/analysis/{findingId}`.
- **Audited as:** `iam:analysis:update`.
- **Errors:** `INVALID_INPUT` when `findingId` is not a 24-character finding ID, or `reason` is empty or longer
  than 500 characters.

The reason, the caller, and the time are kept and shown to anyone who lists suppressed findings, so reviewers can
see who accepted which risk. Suppressing a finding again replaces its reason.

## unsuppress

Shows a suppressed finding again.

- **Permission:** `iam:analysis:update` on `iam/analysis/{findingId}`.
- **Audited as:** `iam:analysis:update`.

Unsuppressing a finding that is not suppressed succeeds and changes nothing.
