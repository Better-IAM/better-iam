# delegations

A delegation lets one AI agent act for one person, within a scope and for a limited time. The person grants it
directly (`grant`) or approves the agent's request (`request`, then `approve` or `deny`). The agent then exchanges its
own API key for short delegated sessions (`assume`) whose identity is the person, so every decision uses the person's
own grants and never more. Agents themselves are managed with [agents](/docs/reference/api/agents). The repository
guide is `docs/agents.md`.

## What a delegated session may do

A delegated session (a `biam_dlg_…` bearer token of session kind `delegated`) acts as the person, and three ceilings
narrow what the person could do:

1. the delegation's scope: `scopes`, a list of actions (wildcards allowed) allowed on every resource, or a `policy`
   document;
2. the agent's `boundary`;
3. the optional scope-down `policy` the agent passed to `assume`.

The limits of the agent key that opened the session also apply: its `scopes` (or session policy) and its issuer's
authority.

A delegation may also hold some actions back for the person to confirm one call at a time: `confirm`, a list of action
patterns accepted by `grant`, `request`, and `approve` (an empty list on `approve` drops them). Those actions are
refused until the person approves that action on that resource ([`requestConfirmation`](#requestconfirmation),
[`decideConfirmation`](#decideconfirmation)).

When the person allows it (`handoff` on `grant`, `request`, or `approve`), the agent may hand part of the delegation on
to another agent with [`handoff`](#handoff); see [Hand-offs](#hand-offs).

Delegated sessions never count as a recent sign-in, cannot manage delegations (apart from `handoff`) or open further
delegated sessions, cannot mint session tokens (`CREDENTIAL_CHAINING_DISABLED`), and cannot obtain assertions. Every use re-validates the
chain: the delegation (active, unexpired, not revoked since the session began), the person, the agent and its sponsor,
the agent's `delegable` setting, and the agent key the session came from. When any link breaks, the session is refused
with `UNAUTHENTICATED`. Policies see `principal.delegated`, `principal.delegationId`, and the agent's keys
([principal keys](/docs/guides/authorization/conditions#principal-keys)), and audit events recorded in the session name
the person as actor with `agentId` and `delegationId` in their session context.

## Lifecycle and who may act

| Status | Meaning |
| --- | --- |
| `pending` | The agent asked with `request` and the person has not decided. `expiresAt` is when the request lapses, seven days after it was made. |
| `active` | The agent may open delegated sessions until `expiresAt`. |
| `denied` | The person turned the request down. |
| `revoked` | Ended early by the person, the agent, its sponsor, or an administrator, or because the person was offboarded or deleted or the agent deleted. |

A lapsed request or an ended delegation keeps its status and reads `expired: true`. One pending or active delegation
may link an agent and a person at a time.

The person decides in their own signed-in session (`grant`, `approve`, `deny`); the agent acts with its own API key
(`request`, `assume`). The people involved (the person, the agent with its own key, and the agent's sponsor) read,
follow (`activity`), and revoke a delegation without any permission (for a hand-off, so does the agent that handed it
on, in its delegated session); anyone else needs `iam:delegations:read` or
`iam:delegations:revoke` on `iam/{delegationId}`, and `list` needs `iam:delegations:read` on the tenant.

## Spending caps

`spend: { period, maxCostUsd?, maxTokens?, maxRequests? }` on `grant`, `request`, `approve` (where `null` removes it),
or `handoff` caps the AI model calls made under the delegation per `minute`, `hour`, `day`, or `month`, with at least
one limit. Every [inference](/docs/reference/api/inference) call in a delegated session of the delegation, or of a
hand-off below it, counts like a budget: past the cap, calls are refused with `BUDGET_EXCEEDED` until the window
resets, and the first refusal is audited as `inference:budget-exceeded` on `delegation:{delegationId}`. Summaries report
the cap and what the current window used as `spend` (`maxCostUsd`, `maxTokens`, `maxRequests`, `usedCostUsd`,
`usedTokens`, `usedRequests`, `resetsAt`). An invalid setting (another period, no limit, or a limit out of range) is
`INVALID_INPUT`.

## Hand-offs

A hand-off is a delegation an agent creates from its own, for another agent, while acting for the person: `requestedBy`
is `handoff`, `parentId` names the delegation above, and `chain` lists the agents above it (the person's own delegate
first). The person allows hand-offs with `handoff: { agents?, depth? }`: `agents` limits them to named agents of the
tenant (at most 20; any agent that accepts delegation when left out), and `depth` (1 to 3, 1 by default) is how many
hand-offs may follow one another. Each hand-off gets the depth left, and the person's `confirm` list travels down with
it.

A hand-off never allows more than its own scope, every delegation above it, the ceilings of every agent in the chain,
and the limits of the session that handed it on (its scope-down policy, its key's scopes, and that key's issuer). Every
use checks the whole chain, so a hand-off stops working when a delegation above it ends, an agent above it is
suspended, loses its sponsor, or stops accepting delegation, or the API key the handing agent acted with is revoked or
expires (a hand-off never lasts past that key). Revoking a delegation revokes the hand-offs below it; when an agent
revokes one from its delegated session, `revokedBy` names the agent. The handing agents' own inference budgets count a
hand-off's model calls too.
Hand-offs do not count toward the rule that one pending or active delegation may link an agent and a person. Policies
see the chain as `principal.delegationChain`.

## activity

Returns what happened under a delegation, newest first: its lifecycle and everything the agent did for the person.

- **Permission:** None for the person, the agent with its own key, or the agent's sponsor; anyone else needs
  `iam:delegations:read` on the delegation.
- **Audited as:** `iam:delegations:read` when read with the permission; not audited for the people involved.
- **Errors:** `NOT_FOUND` when the delegation is not in this tenant (for a caller with the permission);
  `ACCESS_DENIED` for anyone else; `INVALID_INPUT` for a `limit` outside 1 to 500 or a malformed `offset`, `from`, or
  `to`.

The events are those whose resource is the delegation (`delegation:grant`, `delegation:request`,
`delegation:approve`, `delegation:deny`, `delegation:assume`, `delegation:revoke`) and those recorded for the agent's
delegated sessions under it (`sessionContext.delegationId`), allowed and denied, together with the same for every
[hand-off](#hand-offs) below it. It answers the person's question "what did the agent do on my behalf?". Page with `limit` (100 by default) and `offset`, and bound the time with `from`
and `to` (epoch milliseconds).

```ts
const trail = await iam.api.delegations.activity(aliceSession, { tenantId, delegationId });
```

## approve

Approves an agent's pending request, optionally with a different scope, lifetime, or session cap.

- **Permission:** The person the request names, in their own signed-in session with a recent sign-in.
- **Audited as:** `delegation:approve`, with the agent and the new `expiresAt`.
- **Errors:** `NOT_FOUND` when the request is not addressed to you (administrators included); `INVALID_TRANSITION`
  (409) when it is no longer pending or has lapsed; `RECENT_AUTH_REQUIRED` without a recent sign-in;
  `IMPERSONATION_RESTRICTED` from an impersonation session; `DELEGATION_NOT_ALLOWED` or `INVALID_IDENTITY` (409) when
  the agent stopped accepting delegation or is no longer in good standing; `INVALID_INPUT`, `INVALID_ACTION`, or
  `INVALID_POLICY` for a new scope or an out-of-range lifetime.

Pass `scopes` or `policy` (not both) to replace the scope the agent asked for, usually to narrow it; without either,
the requested scope stands. The delegation lasts `expiresInSeconds` from now (300 seconds to one year), by default as
long as the agent asked for (`requestedSeconds`). `maxSessionSeconds` (60 to 43200) caps each delegated session.
`handoff` lets the agent hand work on ([Hand-offs](#hand-offs)). An agent's requested `handoff` counts only when you
state `handoff` here yourself; a plain approval (or `null`) leaves hand-offs out.

```ts
await iam.api.delegations.approve(aliceSession, {
  tenantId,
  delegationId: request.id,
  scopes: ['calendar:read'],
});
```

## assume

Opens a delegated session in which the agent acts for the person, and returns its bearer token once.

- **Permission:** The delegation's agent, with its own API key.
- **Audited as:** `delegation:assume`, with the person, the new session's id, and `durationSeconds`.
- **Errors:** `ACCESS_DENIED` for any other credential (a delegated token cannot open another session); `NOT_FOUND`
  when the delegation is not this agent's; `DELEGATION_PENDING` (409) while the person has not decided;
  `DELEGATION_INACTIVE` (403) when the delegation was denied, revoked, lapsed, or ended, or the person is no longer
  active; `DELEGATION_NOT_ALLOWED` (403) when the agent's `delegable` is off; `LIMIT_EXCEEDED` (409) when the
  delegation already holds 20 live sessions; `INVALID_INPUT` for a `durationSeconds` out of range or a malformed
  `sessionName`; `INVALID_POLICY` or `INVALID_ACTION` for the scope-down `policy`.

The token's identity is the person (`session.identityId`); `session.agentId` and `session.delegationId` name the agent
and the delegation. It lasts `durationSeconds`, from 60 up to the smaller of the agent's `maxDelegatedSessionSeconds`
(3600 when unset) and the delegation's `maxSessionSeconds`, and by default 900 seconds or that limit if it is lower.
It never outlives the delegation or the agent key that opened it. `sessionName` (2 to 64 letters, digits, or `+=,.@_-`)
appears in the session context of audit events. Each call also records `lastUsedAt` on the delegation.

```ts
const { token, expiresAt, session } = await iam.api.delegations.assume(agentKey, {
  tenantId,
  delegationId,
  durationSeconds: 600,
  sessionName: 'triage-run-42',
});
await iam.require({ token, tenantId, action: 'tickets:update', resource: { type: 'ticket', id: 'T-1' } });
```

## deny

Turns down an agent's pending request.

- **Permission:** The person the request names, in their own signed-in session.
- **Audited as:** `delegation:deny`, with the agent.
- **Errors:** `NOT_FOUND` when the request is not addressed to you; `INVALID_TRANSITION` (409) when it is no longer
  pending or has lapsed; `IMPERSONATION_RESTRICTED` from an impersonation session.

No recent sign-in is needed. The request becomes `denied`; the agent sees that when it polls `get`, and may ask again
with a new `request`.

## get

Returns one delegation to the person, the agent, or the agent's sponsor, or to an administrator.

- **Permission:** None for the person, the agent (with its own key), or the agent's sponsor; anyone else needs
  `iam:delegations:read` on the delegation.
- **Audited as:** Not audited for the parties involved; `iam:delegations:read` for administrators.
- **Errors:** `NOT_FOUND` when the delegation is not in this tenant.

An agent that asked with `request` polls this until `status` leaves `pending`. The summary names the agent (with its
model and provider) and the person, the scope as `scopes` (when given as actions) and as the compiled `policy`, who
created it (`requestedBy`), the agent's `reason`, and its times; `expired` is true for a lapsed request or an active
delegation past its end. It never contains session tokens.

## grant

Lets an agent act for you, within a scope and for a limited time.

- **Permission:** Your own signed-in session of the tenant with a recent sign-in; no `iam:*` permission.
- **Audited as:** `delegation:grant`, with the agent, `expiresAt`, and the scopes.
- **Errors:** `DELEGATION_EXISTS` (409) when a pending request or an active delegation already links you and the agent;
  `DELEGATION_NOT_ALLOWED` (403) when the agent does not accept delegation; `INVALID_IDENTITY` (409) when the agent is
  not in good standing; `NOT_FOUND` when the id is not an agent of this tenant; `RECENT_AUTH_REQUIRED` without a
  recent sign-in; `IMPERSONATION_RESTRICTED` from an impersonation session; `ACCESS_DENIED` from an API key, role
  session, session token, or delegated session; `INVALID_INPUT` for a missing or doubled scope or an out-of-range
  lifetime; `INVALID_ACTION` or `INVALID_POLICY` for a scope the catalog does not accept.

Give exactly one of `scopes` (actions, wildcards allowed) or `policy` (a policy document). Either way the scope only
narrows: the agent acts with your grants, so it can never do more than you can. `expiresInSeconds` runs from 300
seconds to one year (30 days by default), and `maxSessionSeconds` (60 to 43200) caps each delegated session below the
agent's own limit. When the agent has already asked, approve its request instead. [`agents.catalog`](/docs/reference/api/agents#catalog)
lists the agents you can delegate to.

```ts
const delegation = await iam.api.delegations.grant(aliceSession, {
  tenantId,
  agentId,
  scopes: ['tickets:read', 'tickets:update'],
  expiresInSeconds: 30 * 86_400,
  maxSessionSeconds: 900,
});
```

`handoff` lets the agent hand parts of the delegation on to other agents ([Hand-offs](#hand-offs)); an invalid setting
(an unknown agent, more than 20 agents, or a depth outside 1 to 3) is `INVALID_INPUT`.

## handoff

Hands part of the delegation an agent acts under on to another agent, for the same person.

- **Permission:** A delegated session (from `assume`) whose delegation allows hand-offs to that agent; no `iam:*`
  permission.
- **Audited as:** `delegation:handoff` on the new delegation, with `parentId`, `fromAgentId`, `toAgentId`, `depth`,
  and the scopes; the actor is the person, with the handing agent in the session context.
- **Errors:** `ACCESS_DENIED` for any credential but a delegated session of the tenant; `DELEGATION_INACTIVE` (403)
  when the delegation (or one above it) has ended; `DELEGATION_NOT_ALLOWED` (403) when the person did not allow
  hand-offs, not to that agent, or no more of them down the line, when the agent is already in the chain, or when it
  does not accept delegation; `INVALID_IDENTITY` (409) when it is not in good standing; `NOT_FOUND` when the id is not
  an agent of this tenant; `LIMIT_EXCEEDED` (409) when the delegation already holds 20 live hand-offs; `INVALID_INPUT`,
  `INVALID_ACTION`, or `INVALID_POLICY` for the scope, `confirm`, or an `expiresInSeconds` outside 60 seconds to one
  year.

Give `agentId` and exactly one of `scopes` or `policy`. The result is a new active delegation from the same person to
that agent (see [Hand-offs](#hand-offs) for what bounds it). It lasts `expiresInSeconds` (one hour by default), never
past the delegation above. It keeps the person's `confirm` list plus any `confirm` given here, and `maxSessionSeconds`
never above the delegation above. `reason` (up to 1024 characters) is shown to the person. Pass the new delegation's
`id` to the other agent, for example in an A2A message; it opens its own sessions for the person with `assume` and its
own key.

```ts
const handoff = await iam.api.delegations.handoff(
  { token: delegatedToken },
  { tenantId, agentId: researcherId, scopes: ['documents:read'], reason: 'Find sources for the report' },
);
```

## issueToken

Gives an agent acting for a person a delegation token: a short-lived signed JWT that shows one service outside Better
IAM that the agent acts for that person.

- **Permission:** A delegated session (from `assume`); no `iam:*` permission. The deployment needs the `a2a` option,
  because its card keys sign the token.
- **Audited as:** `delegation:token-issue` on the delegation, with the `audience`, `tokenId`, `expiresAt`, and the
  scopes; the actor is the person, with the agent in the session context.
- **Errors:** `FEATURE_DISABLED` (403) without the `a2a` option; `ACCESS_DENIED` for any credential but a delegated
  session of the tenant; `DELEGATION_INACTIVE` (403) when the delegation or one above it has ended;
  `DELEGATION_NOT_ALLOWED` (403) when:
  - an agent in the chain does not list the audience in its `tokenAudiences`;
  - some limit on the session does not allow a scope outright;
  - a scope is one the person confirms call by call;
  - a deny among the person's own grants could touch a scope.

  `INVALID_INPUT` for an audience that is not an http(s) URL or other absolute URI, that has user info, a query or a
  fragment, or that contains `*`; for a malformed scope (letters, digits, `:_./-`, and `*`; at most 50); or for a
  `lifetimeSeconds` outside 30 to 3600. `RATE_LIMITED` (429) past the per-delegation budget.

Give `audience`, the one service the token is for. It must match the
[`tokenAudiences`](/docs/reference/api/agents#profile-and-ceiling) of the agent and of every agent that handed the work
to it. `scopes` defaults to the delegation's own scopes (none for a delegation given as a policy). Each scope must be
allowed outright, on every resource and without conditions, by every limit the session is under: the delegation and
those above it, the agents' ceilings, the session's scope-down policy, its key's scopes and issuer, and the person's
and tenant's boundaries. No scope may be an action the person confirms call by call (`confirm` anywhere in the
chain), nor one a deny statement among the person's own grants could touch. The token lasts `lifetimeSeconds` (300 by
default), never past the session or any delegation in the chain, and is recorded until it expires so a live check can
re-examine it.

The result is `{ token, tokenType: 'biam-delegation+jwt', tokenId, issuer, audience, scopes, chain, expiresAt,
expiresIn }`. The JWT's header is `{ alg, kid, typ: 'biam-delegation+jwt', jku }`. Its claims are `iss`, `sub` (the
person), `aud`, `iat`, `nbf`, `exp`, `jti`, `tenant_id`, `delegation_id`, `act`, and `scope` (space-separated, when
there are scopes). `act` is the agent (`{ sub }`), with the agents that handed the work on nested inside
(RFC 8693 section 4.1). Services verify it with `verifyDelegationToken` from `@better-iam/a2a` against the deployment's
card keys. A service next to the deployment can use `iam.a2a.verifyDelegationToken(token, { audience, live: true })`.
It re-checks the delegation chain, the person, the agents and the acting agent's key, the audience, and the scopes
against the current state, so a revocation or a narrowed limit takes effect before the token expires.

```ts
const { token } = await iam.api.delegations.issueToken(
  { token: delegatedToken },
  { tenantId, audience: 'https://api.calendar.example', scopes: ['calendar:read'] },
);
```

## list

Lists the tenant's delegations, newest first, filtered by agent, person, or status.

- **Permission:** `iam:delegations:read` on the tenant.
- **Audited as:** `iam:delegations:read`.

`status` is `pending`, `active`, `denied`, or `revoked`; lapsed requests and ended delegations keep their status and
carry `expired: true`.

## listMine

Returns your own delegations, newest first: the agents acting or asking to act for you, or, for an agent, the people it acts for.

- **Permission:** A person's own signed-in session, or an agent's own API key, in the tenant.
- **Audited as:** Not audited; it only reads.
- **Errors:** `ACCESS_DENIED` for other credentials (role sessions, session tokens, delegated sessions, a session of
  another tenant); `IMPERSONATION_RESTRICTED` from an impersonation session.

Every status is included, so a settings page can show requests to decide, delegations to revoke, and the history.

## request

Asks a person to delegate to the calling agent, and emails them the request when the deployment sends email.

- **Permission:** The agent's own API key.
- **Audited as:** `delegation:request`, with the person and the scopes.
- **Errors:** `ACCESS_DENIED` for any credential but an agent's own key; `RATE_LIMITED` (429) when the agent asks too
  often; `NOT_FOUND` when no active person of the tenant has that id or email; `DELEGATION_EXISTS` (409) when a pending
  request or an active delegation already links the agent and the person; `DELEGATION_NOT_ALLOWED` when the agent's
  `delegable` is off; `INVALID_INPUT` without exactly one of `subjectId` and `subjectEmail`, without a `reason`, or for
  scope and lifetime values as in `grant`.

Name the person by `subjectId` or `subjectEmail`; `reason` (up to 1024 characters) is shown to them. The request waits
up to seven days for their decision. `expiresInSeconds` is how long the delegation will last once approved (reported as
`requestedSeconds`); the person may change it and the scope when approving. When the person has an email address and
the deployment configures `sendEmail`, they receive the `delegation-request` email, which links to your approval page
through `links.delegation` in the email templates. Each request counts toward a per-agent rate limit, even when it is
refused.

```ts
const request = await iam.api.delegations.request(agentKey, {
  tenantId,
  subjectEmail: 'alice@acme.test',
  scopes: ['calendar:read', 'calendar:write'],
  reason: 'Schedule your interviews for next week',
  expiresInSeconds: 7 * 86_400,
});
```

## revoke

Ends a pending or active delegation and deletes its live delegated sessions at once.

- **Permission:** None for the person, the agent (with its own key), or the agent's sponsor; anyone else needs
  `iam:delegations:revoke` on the delegation.
- **Audited as:** `delegation:revoke`, with the agent, the person, `sessionsEnded`, `handoffsRevoked` (when hand-offs
  below it ended too), and the `reason`; an administrator's call also as `iam:delegations:revoke`.
- **Errors:** `INVALID_TRANSITION` (409) when it is already denied or revoked; `NOT_FOUND` when it is not in this
  tenant.

`reason` (up to 512 characters) goes to the audit event. A revoked delegation cannot be used again; the agent needs a
new `grant` or an approved `request`. To stop an agent for everyone at once, suspend it with
[`agents.suspend`](/docs/reference/api/agents#suspend).

## requestConfirmation

Asks the person an agent acts for to confirm one action the delegation holds back.

- **Permission:** None beyond the agent's delegated session (from `assume`) in the delegation's tenant.
- **Audited as:** `delegation:confirmation-request`, on the delegation, with the confirmation id, the action, and the
  resource.
- **Errors:** `ACCESS_DENIED` for any credential other than a delegated session; `INVALID_INPUT` when the action does
  not match the delegation's `confirm` patterns, or for a malformed action, resource, reason, or `validSeconds`
  outside 30 to 3600; `RATE_LIMITED` (429) when the delegation asks too often.

A delegation created with `confirm` (action patterns, on `grant`, `request`, or `approve`) refuses those actions to
its delegated sessions until the person approves them one call at a time: the decision is refused with the internal
reason `CONFIRMATION_REQUIRED` (callers see an ordinary denial). The agent names the `action` and the `resource` it
wants to act on and a `reason` for the person; the request waits up to 30 minutes and is emailed to the person
(template `delegation-confirmation`) when the deployment sends email. Asking again for the same action and resource
while a request is pending returns that request. Once approved, exactly that action on that resource is allowed for
`validSeconds` (300 by default); the agent polls `getConfirmation` and retries.

```ts
const request = await iam.api.delegations.requestConfirmation(delegatedSession, {
  tenantId,
  action: 'documents:delete',
  resource: { type: 'document', id: 'q3-draft' },
  reason: 'You asked me to clean up the drafts folder',
  validSeconds: 120,
});
```

## decideConfirmation

Approves or rejects an agent's pending confirmation request.

- **Permission:** None beyond the person's own session (not impersonated) of the tenant; only the person the request
  asks may decide it.
- **Audited as:** `delegation:confirm` or `delegation:reject`, on the delegation, with the confirmation id, the
  action, and the resource.
- **Errors:** `NOT_FOUND` when the request does not exist or asks someone else; `INVALID_TRANSITION` (409) when it
  was already decided or has lapsed; `DELEGATION_INACTIVE` (403) when the delegation ended meanwhile;
  `ACCESS_DENIED` from any other credential; `INVALID_INPUT` when `approve` is not a boolean.

`approve: true` opens the requested action on the requested resource, for the agent acting for the person under this
delegation, until `validSeconds` after the decision. `approve: false` rejects it; nothing opens. No recent sign-in is
needed, so the person can answer from a notification right away.

## getConfirmation

Returns one confirmation request to the person it asks or to the agent that made it.

- **Permission:** None: the person's own session, the agent's own key, or a delegated session of the same delegation.
- **Audited as:** Not audited; it only reads.
- **Errors:** `NOT_FOUND` when the request does not exist or is not visible to the caller; `ACCESS_DENIED` for any
  other credential.

Agents poll it while `status` is `pending`. `expired` is true for a pending request past its decision window and for
an approval past its validity.

## listConfirmations

Lists confirmation requests newest first: those addressed to the caller, or those the calling agent made.

- **Permission:** None: a person's own session sees the requests that ask them, an agent's own key every request it
  made, and a delegated session those of its delegation.
- **Audited as:** Not audited; it only reads.
- **Errors:** `ACCESS_DENIED` for any other credential or tenant.

Filter with `status` (`pending`, `approved`, or `rejected`). It backs an "actions waiting for your confirmation" list.
