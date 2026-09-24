# quotas

API usage plans: throttles (a token bucket of `ratePerSecond` holding at most `burst`) and period limits (per minute,
hour, day, week or month) on a **meter** you name, such as `requests` or `exports`. Plans apply to API keys, agents,
identities and groups, or to everyone in the tenant as the meter's default. Applications count use with
`iam.quotas.consume` / `enforce` (the request's credential) or `consumeFor` (a subject your code identified), and
callers read what is left with `status`. Counters are stored in the database, so every server instance agrees. The
repository guide is `docs/quotas.md`.

## Which plan applies

For each meter, the most specific plan wins: the API key the request presents, then the acting agent of a delegated
session, the identity, one of its groups (highest `priority`, then name), and finally the tenant's `default` plan. A
meter no plan covers is unlimited (`plan: null`). With `scope: 'tenant'` everyone the plan covers shares one set of
counters; with `scope: 'subject'` each API key, agent or person has their own.

## createPlan

Defines a plan for a meter with a `throttle`, `limits`, or both.

- **Permission:** `iam:quotas:manage` on `iam/quotas/{name}`.
- **Audited as:** `quota:plan-create`.
- **Errors:** `CONFLICT` (409) when the name is taken or the tenant already has a default plan for the meter;
  `INVALID_INPUT` without a throttle or limits, for two limits of one period, a limit below 1, an unknown period or time
  zone, a malformed name or meter, or more than five `alertThresholds`.

Day, week (Monday to Sunday) and month windows start at local midnight in `timeZone` (default `UTC`); minutes and hours
are UTC. `alertThresholds` are percentages of each period limit recorded once per window as `quota:threshold`.

## updatePlan

Changes a plan; fields left out keep their value, `throttle: null` and `description: null` clear them, and `limits`
replaces the list. The meter cannot change. Windows in progress keep their counts under the new limits.

- **Permission:** `iam:quotas:manage` on `iam/quotas/{name}`.
- **Audited as:** `quota:plan-update`.
- **Errors:** `NOT_FOUND` (404); `CONFLICT` (409) when making it the default and another plan already is;
  `INVALID_INPUT` as for `createPlan`.

## deletePlan

Deletes a plan with its assignments and counters.

- **Permission:** `iam:quotas:manage` on `iam/quotas/{name}`.
- **Audited as:** `quota:plan-delete`, with how many assignments went.

## listPlans

Every plan of the tenant, by name, with how many subjects are assigned to each.

- **Permission:** `iam:quotas:read` on `iam/quotas`.

## getPlan

One plan.

- **Permission:** `iam:quotas:read` on `iam/quotas/{name}`.
- **Errors:** `NOT_FOUND` (404).

## assign

Assigns a plan to an API key (`subjectType: 'apiKey'` with the key's `credentialId`), an identity, or a group,
replacing the subject's plan for the same meter.

- **Permission:** `iam:quotas:manage` on `iam/quotas/{plan}`.
- **Audited as:** `quota:assign`.
- **Errors:** `NOT_FOUND` (404) for an unknown plan, a subject outside the tenant, a deleted identity, or a session
  that is not an API key; `INVALID_INPUT` for another `subjectType`.

## unassign

Removes a subject's plan for a meter; `removed` says whether there was one.

- **Permission:** `iam:quotas:manage` on `iam/quotas`.
- **Audited as:** `quota:unassign` when something was removed.

## listAssignments

Assignments, optionally of one `plan`, with each subject's name (an API key's label).

- **Permission:** `iam:quotas:read` on `iam/quotas`.

## usage

Every subject's use of a plan in the current windows, the most used first. Subjects are named `identity:{id}`,
`key:{credentialId}`, or `tenant` for a tenant-scoped plan.

- **Permission:** `iam:quotas:read` on `iam/quotas/{plan}`.

## reset

Starts one `subject`'s counters and throttle over (as `usage` names it), or every subject's when none is given.

- **Permission:** `iam:quotas:manage` on `iam/quotas/{plan}`.
- **Audited as:** `quota:reset`, with how many counters went.

## status

The caller's own plan for a meter and what is left in each window, without counting.

- **Permission:** None beyond a session of the tenant.
- **Audited as:** Not audited.
- **Errors:** `ACCESS_DENIED` for a session of another tenant.

## consume

Counts `cost` (default 1) units of a meter for the caller's own session, or refuses without counting anything when
the throttle or a period limit would be exceeded: `allowed: false` with `reason` (`throttle` or the period) and
`retryAfterMs` (absent when the cost can never fit).

- **Permission:** None beyond a session of the tenant.
- **Audited as:** `quota:threshold` when use first reaches an alert threshold in a window, and `quota:exceeded`
  (outcome `deny`) at a window's first refusal.
- **Errors:** `ACCESS_DENIED` for a session of another tenant; `INVALID_INPUT` for a malformed meter or a cost outside
  1 to 1,000,000,000.
