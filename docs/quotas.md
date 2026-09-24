# API usage plans and quotas

Usage plans limit how much of your API (or anything else you count) a caller may use, the way AWS API Gateway usage
plans or an API gateway's rate limiting do, but decided by who the caller is in Better IAM: the API key they present,
the agent acting for them, the person, their groups, or the whole organization.

```ts
await iam.api.quotas.createPlan(admin, {
  tenantId,
  name: 'free',
  meter: 'requests',
  throttle: { ratePerSecond: 5, burst: 20 },
  limits: [
    { period: 'day', limit: 1_000 },
    { period: 'month', limit: 20_000 },
  ],
  default: true, // everyone in the organization without a plan of their own
  alertThresholds: [80, 100],
});

// In a request handler:
const decision = await iam.quotas.enforce({ headers: request.headers, tenantId, meter: 'requests' });
// decision.limits: [{ period: 'day', limit: 1000, used: 42, remaining: 958, resetAt }, ...]
```

`enforce` throws `QUOTA_EXCEEDED` (429) when the call would go over, carrying `retryAfterMs`; over HTTP the error
answer has a `Retry-After` header. `consume` returns the same decision (`allowed: false`, with `reason` and
`retryAfterMs`) instead of throwing. A refused call counts nothing.

## Plans

A plan counts one **meter**: a name you choose for what is being counted (`requests`, `exports`, `emails`, `tokens`).
It limits it in two ways, either or both:

- A **throttle**: a token bucket that refills at `ratePerSecond` and holds at most `burst` tokens, so short bursts pass
  and sustained rates are capped. A refused call learns how long until enough tokens are back.
- Period **limits**: at most one each per `minute`, `hour`, `day`, `week` and `month`. Minutes and hours are UTC; days,
  weeks (Monday to Sunday) and months start at local midnight in the plan's `timeZone` (default `UTC`), daylight saving
  time included. A refused call learns when the window ends.

`consume` takes a `cost` (default 1) for calls that count more than one unit: a batch of 50 messages, a large export.
A cost above a plan's burst or period limit can never succeed; such refusals carry no `retryAfterMs`.

`scope: 'subject'` (the default) gives each API key, agent or person their own counters. `scope: 'tenant'` makes
everyone the plan covers share one set: an organization's pooled monthly allowance.

Counters are stored in the database, so every server instance sees the same totals and the same token bucket. Each
consumption is one short transaction; old counters are removed by `iam.sweepExpired()`.

## Who gets which plan

Plans are assigned to API keys (`subjectType: 'apiKey'`, the key's `credentialId`), identities (people, service
accounts and agents), and groups. For each meter the most specific plan applies:

1. a plan assigned to the API key the request presents;
2. a plan assigned to the agent acting in a delegated session;
3. a plan assigned to the identity;
4. a plan assigned to one of the identity's groups (the highest `priority` wins, then the name);
5. the tenant's `default` plan for the meter (one per meter).

A meter no plan covers is unlimited: `consume` answers `allowed: true` with `plan: null`.

```ts
await iam.api.quotas.assign(admin, { tenantId, plan: 'partner', subjectType: 'apiKey', subjectId: key.credentialId });
await iam.api.quotas.assign(admin, { tenantId, plan: 'internal', subjectType: 'group', subjectId: staffGroupId });
```

Assigning replaces the subject's plan for the same meter; `unassign` removes it.

## Callers

- `iam.quotas.consume` / `enforce({ token | headers, tenantId, meter, cost? })`: count for the request's credential.
  The credential must be a session of the tenant.
- `iam.quotas.status({ token | headers, tenantId, meter })`: what is left, without counting, for a "usage this month"
  display. Also `quotas.status` over HTTP and the typed client.
- `quotas.consume` over HTTP: a caller counting its own use (an API gateway forwarding its client's credential).
- `iam.quotas.consumeFor({ tenantId, identityId, apiKeyId?, meter, cost? })`: for work your code attributes itself,
  such as a background export; events are recorded as `deployment-operator`.

## Managing plans

| Method                                | Permission                                  | Audited as                          |
| ------------------------------------- | ------------------------------------------- | ----------------------------------- |
| `createPlan`, `updatePlan`, `deletePlan` | `iam:quotas:manage` on `iam/quotas/{plan}` | `quota:plan-create`, `-update`, `-delete` |
| `assign`                              | `iam:quotas:manage` on `iam/quotas/{plan}`  | `quota:assign`                      |
| `unassign`                            | `iam:quotas:manage` on `iam/quotas`         | `quota:unassign`                    |
| `listPlans`, `listAssignments`        | `iam:quotas:read` on `iam/quotas`           | the read                            |
| `getPlan`, `usage`                    | `iam:quotas:read` on `iam/quotas/{plan}`    | the read                            |
| `reset`                               | `iam:quotas:manage` on `iam/quotas/{plan}`  | `quota:reset`                       |

`usage` lists every subject's use in the current windows, the most used first; `reset` starts one subject's counters
(`subject` as `usage` names it, such as `identity:usr_…` or `key:ses_…`) or everyone's over. Deleting a plan removes
its assignments and counters.

## Alerts

`alertThresholds` (up to five percentages) record `quota:threshold` once per window when use first reaches that share
of a period limit, and every window's first refusal records `quota:exceeded` (outcome `deny`). Subscribe a
[webhook](events.md) to `quota:*` to email a customer at 80% of their monthly allowance, or to page someone when an
integration starts getting refused.
