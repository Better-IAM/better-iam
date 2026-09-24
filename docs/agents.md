# AI agents

Better IAM treats AI agents as accounts of their own. An agent is an identity of kind `agent`: like a service account
it holds API keys and never signs in, and like every identity it gets roles, groups, and policies. Three things set it
apart:

- **A sponsor.** Every agent has a person accountable for it. The agent's credentials work only while its sponsor is an
  active, unexpired person of the same organization. When the sponsor leaves, offboarding hands the agent to their
  successor, or the agent stops until an administrator names a new sponsor. No agent outlives the human answerable for
  it.
- **A ceiling.** An agent's `boundary` policy caps everything it does, whatever its roles say and whoever it acts for.
- **Delegation.** A person can let an agent act on their behalf, within a scope and for a limited time. The agent then
  opens short delegated sessions that act as the person, never with more than the person has.

Policies see agents too: `principal.kind` is `agent` for an agent's own key, and every decision carries
`principal.delegated`, plus `principal.agentId`, `principal.agentSponsorId`, `principal.agentModel`,
`principal.agentProvider` and `principal.delegationId` whenever an agent is involved, and `principal.delegationChain`
(every agent between the person and the acting one) in delegated sessions.

## Registering an agent

```ts
const agent = await iam.api.agents.create(admin, {
  tenantId,
  name: 'Support triage',
  purpose: 'Labels and routes incoming support tickets',
  model: 'claude-sonnet-5',
  provider: 'anthropic',
  protocols: ['mcp'],
  sponsorId: alice.id, // defaults to the caller when the caller is a person of the organization
  boundary: {
    version: 1,
    statements: [{ effect: 'allow', actions: ['tickets:*'], resources: ['ticket/*'] }],
  },
});

// Keys work as for service accounts: typed `biam_key_…` tokens, bounded by the issuer's authority.
const { token } = await iam.api.credentials.create(admin, {
  tenantId,
  identityId: agent.id,
  name: 'production',
  scopes: ['tickets:read', 'tickets:update'],
});
```

Creating agents needs `iam:agents:create`; reading `iam:agents:read`; changing `iam:agents:update`; deleting
`iam:agents:delete` and a recent sign-in. The tenant plan limit `agents` caps how many an organization may register.

| Profile field                | Meaning                                                                                                      |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `sponsorId`                  | The accountable person (active user of the same tenant).                                                     |
| `model`, `provider`          | What the agent runs on. Policies see `principal.agentModel` and `principal.agentProvider`.                   |
| `purpose`, `url`             | Shown to people deciding whether to delegate to it.                                                          |
| `protocols`                  | Informational list, such as `mcp` and `a2a`.                                                                 |
| `boundary`                   | A ceiling over everything the agent does. Changes apply to live sessions at once.                            |
| `delegable`                  | `false` refuses delegations and ends the use of existing ones until turned back on.                          |
| `maxDelegatedSessionSeconds` | The longest delegated session the agent may hold (60 to 43200; 3600 by default).                             |
| `tokenAudiences`             | Services outside Better IAM it may present delegations to ([tokens](#calling-other-services-as-the-person)). |

Agents can also be kept in [configuration as code](policies.md#configuration-as-code): the `agents` kind names each
agent with its sponsor's email and its profile (keys stay runtime state).

`agents.get` reports the agent's **standing**: `ok`, `suspended`, `expired`, `deleted`, `sponsor-missing`, or
`sponsor-inactive`. Anything other than `ok` means every credential of the agent is refused.

## The kill switch

A sponsor manages their agents from their own session without any permission: `agents.listMine` lists them, and
`agents.suspend` stops one at once. A suspended agent's keys are refused, and its live delegated sessions and session
tokens end immediately. Keys are kept, so `agents.resume` restores the agent as it was. A sponsor can resume only an
agent they suspended themselves; lifting an administrator's suspension takes `iam:agents:update` and a recent sign-in.

```ts
await iam.api.agents.suspend(aliceSession, { tenantId, agentId, reason: 'Looping on the wiki' });
```

In an incident, `agents.suspendAll` is the organization-wide emergency stop: it suspends every active agent at once,
or only those of one `sponsorId` or running on one `provider` or `model`. It needs `iam:agents:update` on the tenant but
no recent sign-in, so it works in a hurry. It is audited as `agent:suspend-all` and as `agent:suspend` for each agent.
Agents come back one at a time with `resume`.

```ts
await iam.api.agents.suspendAll(admin, {
  tenantId,
  reason: 'Prompt injection incident',
  provider: 'acme-llm',
});
```

Deleting an agent (`agents.delete`) ends its keys and sessions, revokes every delegation to it, and leaves a tombstone
so audit records stay readable.

## Delegation: acting on a person's behalf

A delegation lets one agent act for one person. The delegated session's identity is the person, so the decision uses
the person's grants, and three ceilings apply on top:

1. the delegation's **scope** (`scopes` as an action list, or a `policy` document);
2. the agent's **boundary**;
3. an optional scope-down `policy` the agent passes when it opens the session.

The limits of the agent key that opened the session (its `scopes` or session policy, and its issuer's authority) bound
the session as well. The agent can therefore never do more than the person could, nor more than the person agreed to,
nor more than the agent (or the key it used) is allowed to do in general. Delegated sessions never count as a recent
sign-in, never act as an owner or root administrator, cannot manage delegations (apart from handing work on, when the
person allows it) or mint further credentials, and cannot obtain stateless assertions.

### Granting directly

```ts
const delegation = await iam.api.delegations.grant(aliceSession, {
  tenantId,
  agentId: agent.id,
  scopes: ['tickets:read', 'tickets:update'],
  expiresInSeconds: 30 * 86_400, // 5 minutes to 1 year; 30 days by default
  maxSessionSeconds: 900, // optional cap on each delegated session
});
```

Granting needs the person's own session with a recent sign-in. One pending request or active delegation may link an
agent and a person at a time.

### Asking for consent

An agent can ask a person for a delegation with its own key. The request waits up to seven days and, when the
deployment sends email, the person gets a `delegation-request` email (with `links.delegation` in the email templates
pointing at your approval page). The agent polls `delegations.get` until the status changes. Approving, like granting,
needs a recent sign-in; denying does not.

```ts
const request = await iam.api.delegations.request(agentKey, {
  tenantId,
  subjectEmail: 'alice@acme.test',
  scopes: ['calendar:read', 'calendar:write'],
  reason: 'Schedule your interviews for next week',
  expiresInSeconds: 7 * 86_400,
});

// Alice approves, possibly narrowing what was asked for:
await iam.api.delegations.approve(aliceSession, {
  tenantId,
  delegationId: request.id,
  scopes: ['calendar:read'],
});
// or: await iam.api.delegations.deny(aliceSession, { tenantId, delegationId: request.id });
```

Requests are rate limited per agent.

### Acting

```ts
const { token, expiresAt, session } = await iam.api.delegations.assume(agentKey, {
  tenantId,
  delegationId: delegation.id,
  durationSeconds: 600,
  sessionName: 'triage-run-42',
});
// token is a `biam_dlg_…` bearer credential; session.identityId is Alice, session.agentId the agent.
await iam.require({
  token,
  tenantId,
  action: 'tickets:update',
  resource: { type: 'ticket', id: 'T-1' },
});
```

A delegated session lasts 60 seconds up to the agent's `maxDelegatedSessionSeconds` and the delegation's
`maxSessionSeconds` (15 minutes or less by default), and never past the delegation or the agent key that opened it. At
most 20 live sessions may exist per delegation.

Every use re-validates the whole chain: the delegation (active, unexpired, not revoked since the session began), the
person (active), the agent (active, delegable, sponsor active) and the agent's key (under its own rules, including its
issuer's authority and network blocks). If any link breaks, the session is refused with `UNAUTHENTICATED`.

### Revoking

The person, the agent's sponsor, the agent itself, or an administrator with `iam:delegations:revoke` can revoke a
delegation. Its sessions end at once. Offboarding or deleting the person revokes every delegation they gave; deleting
the agent revokes every delegation to it.

People see their delegations with `delegations.listMine`; agents see theirs the same way with their key.
Administrators list them with `delegations.list` (`iam:delegations:read`). People pick an agent to delegate to from
`agents.catalog`: the active, delegable agents of their organization with their purpose, model, and sponsor.

### Confirming sensitive actions one at a time

A delegation can hold some actions back until the person confirms each call: pass `confirm` (action patterns) when
granting, requesting, or approving. A delegated session is refused those actions until the person approves that
action on that exact resource; the approval then opens one call, made within `validSeconds` (the call uses it up; its
status becomes `used`). Batch and listing checks (`authorizeMany`, `listAccessible`) see an approval without using it.
This is a human-in-the-loop check in the spirit of OpenID CIBA: the agent asks, the person answers from wherever they
are.

```ts
await iam.api.delegations.grant(aliceSession, {
  tenantId,
  agentId: agent.id,
  scopes: ['documents:*'],
  confirm: ['documents:delete', 'documents:share'],
});

// The agent, with its delegated session, asks before deleting:
const request = await iam.api.delegations.requestConfirmation(delegated, {
  tenantId,
  action: 'documents:delete',
  resource: { type: 'document', id: 'q3-draft' },
  reason: 'You asked me to clean up the drafts folder',
  validSeconds: 120, // 30 to 3600; 300 by default
});
// Alice gets a `delegation-confirmation` email and answers from her own session:
await iam.api.delegations.decideConfirmation(aliceSession, {
  tenantId,
  confirmationId: request.id,
  approve: true,
});
// The agent polls delegations.getConfirmation, then retries the delete.
```

Requests wait up to 30 minutes for a decision; asking again for the same action and resource returns the pending
request. Only actions that match `confirm` can be requested. The refusal of an unconfirmed action is recorded like any
denied decision (callers see `ACCESS_DENIED`; the internal reason is `CONFIRMATION_REQUIRED`), so agents should check
the delegation's `confirm` list (`delegations.get`) and ask first. `delegations.listConfirmations` lists the requests
a person has to answer, or an agent's own.

### Capping what an agent spends for you

A person can cap the AI model calls an agent makes on their behalf with `spend` on `grant`, `request` or `approve`:
`maxCostUsd`, `maxTokens` and/or `maxRequests` per `minute`, `hour`, `day` or `month`.

```ts
await iam.api.delegations.grant(aliceSession, {
  tenantId,
  agentId: agent.id,
  scopes: ['inference:invoke', 'documents:read'],
  spend: { period: 'day', maxCostUsd: 5 },
});
```

Every [inference](inference.md) call made under the delegation, or under a hand-off below it, counts against the cap
like a budget: past it, calls are refused with `BUDGET_EXCEEDED` until the window resets, and the first refusal is
audited as `inference:budget-exceeded` on `delegation:{id}`. The delegation's summary reports the cap with what the
current window has used (`spend.usedCostUsd`, `usedTokens`, `usedRequests`, `resetsAt`), so a consent screen can show
"$0.42 of $5 today". `approve` can change a requested cap or remove it with `spend: null`; a hand-off may carry a
tighter cap of its own. The agent's own budgets and the organization's budgets apply as well.

### Handing work on to other agents

Agents increasingly call other agents: an assistant asks a research agent over A2A, a planner hands a step to a
specialist. When the person allows it, the agent acting for them can hand part of its delegation on. The other agent
then acts for the same person, never with more than the handing agent had.

```ts
// Alice lets her assistant hand work on, only to the research agent, one level deep:
const delegation = await iam.api.delegations.grant(aliceSession, {
  tenantId,
  agentId: assistant.id,
  scopes: ['documents:*'],
  handoff: { agents: [researcher.id], depth: 1 }, // omit agents for any delegable agent; depth 1 to 3
});

// The assistant, in its delegated session, hands a narrower part on:
const handoff = await iam.api.delegations.handoff(
  { token: assistantSession.token },
  {
    tenantId,
    agentId: researcher.id,
    scopes: ['documents:read'],
    reason: 'Find sources for the report',
  },
);
// It passes handoff.id to the researcher (over A2A: withHandoff(message, handoff.id) from @better-iam/a2a, read back
// with handoffOf(params)), which opens its own sessions for Alice:
const research = await iam.api.delegations.assume(researcherKey, {
  tenantId,
  delegationId: handoff.id,
});
```

A hand-off is a delegation of its own (`requestedBy: 'handoff'`, with `parentId` and the `chain` of agents above it),
so the receiving agent opens sessions with its own key and every action is attributed to it. Its use is bounded by:

- its own scope, the delegation above it, and every delegation further up;
- the ceilings of every agent in the chain, and of the receiving agent;
- the limits of the session that handed it on: its scope-down policy, its key's scopes, and that key's issuer.

Every use checks the whole chain. If a delegation above ends, or an agent in the chain is suspended or loses its
sponsor, the hand-off stops working at once. Revoking a delegation revokes the hand-offs below it (audited as
`handoffsRevoked`). The person's `confirm` list travels down the chain, so the receiving agent asks the same person to
confirm the same actions. No agent may appear twice in a chain, a delegation may hold at most 20 live hand-offs, and
each lasts an hour by default (`expiresInSeconds`, never past the delegation above).

`principal.delegationChain` lists the agents from the person's own delegate to the acting one. Policies can use it to
keep, say, research agents away from some data whoever hands them the work:

```json
{
  "effect": "deny",
  "actions": ["documents:read"],
  "resources": ["document/hr-*"],
  "conditions": { "ArrayContains": { "principal.delegationChain": ["<research agent id>"] } }
}
```

A hand-off also ends when the API key the handing agent acted with is revoked or expires, and never lasts past it, so
revoking a compromised agent's key stops everything it handed on. The handing agent's own budgets count the hand-off's
model calls too. The person sees hand-offs in `delegations.listMine` and can revoke each one. When an agent revokes a
hand-off from its delegated session, `revokedBy` names the agent. A delegation's `activity` includes everything done
under the hand-offs below it. An agent's request (`delegations.request`) may ask for `handoff`, but hand-offs widen what
happens in the person's name, so they count only when the person states `handoff` themselves when approving; a plain
approval leaves them out.

### Calling other services as the person

A delegated session works wherever Better IAM decides. Other services, such as a partner's API or your own services
that do not call Better IAM, need proof they can check on their own. `delegations.issueToken` gives the agent a
**delegation token**: a short-lived JWT, signed with the deployment's [card keys](#attested-agent-cards) (the `a2a`
option), that names the person as `sub` and the agent as the actor (`act`, as in OAuth token exchange, RFC 8693).

```ts
// The agent, in its delegated session:
const { token, expiresAt } = await iam.api.delegations.issueToken(delegated, {
  tenantId,
  audience: 'https://api.calendar.example', // exactly one service
  scopes: ['calendar:read'], // optional: the delegation's own scopes by default
  lifetimeSeconds: 300, // 30 to 3600; 300 by default
});
await fetch('https://api.calendar.example/events', {
  headers: { authorization: `Bearer ${token}` },
});
```

The token's header is `{ alg, kid, typ: 'biam-delegation+jwt', jku }`. Its claims are:

- `iss`, `aud` (one service), `iat`, `nbf`, `exp` and `jti`;
- `sub` (the person), `tenant_id` (their organization) and `delegation_id`;
- `act: { sub: agentId }`. When the work was handed on, the agents that handed it are nested inside:
  `act: { sub: researcher, act: { sub: assistant } }`;
- `scope` (space-separated) when the delegation was given as scopes.

What the token may say is bounded twice:

- **Where it goes.** The audience must match the `tokenAudiences` of the agent's profile, and of every agent that
  handed the work on. An administrator sets them with `iam:agents:update`, and `agents.catalog` shows them to people
  choosing an agent. An agent without `tokenAudiences` gets no tokens. Entries are http(s) URLs or other absolute URIs
  (`urn:acme:ledger`), without user info, query or fragment. In a URL, `*` may start the host (`https://*.acme.com`
  matches any subdomain of `acme.com`) and may appear in the path (`https://api.acme.com/v1/*`). A URL without a path
  matches only the root. Scheme, host and port must otherwise match exactly. A requested audience never contains `*`.
- **What it claims.** Every scope must be allowed outright, on every resource and without conditions, by every limit
  the session is under: the delegation and those above it, the agents' ceilings, the session's scope-down policy, the
  key's scopes and issuer, and the person's and organization's boundaries. A delegation given as a resource-limited
  policy therefore carries no scopes. Two more rules keep a token from saying more than the person would:
  - no scope may be an action the person confirms call by call (`confirm`, anywhere in the chain);
  - no scope may be one a deny statement among the person's own grants could touch, whatever its resources or
    conditions (a token carries neither).

  The scopes say what the person allowed. The service still decides what the person may do there.

Tokens last 5 minutes by default and never outlive the delegated session or any delegation in the chain. Issuing is
rate limited per delegation and audited as `delegation:token-issue` (with the audience and token id), so it shows in
`delegations.activity`. Each issued token is also recorded until it expires, for live verification. Without the `a2a`
option, `issueToken` answers `FEATURE_DISABLED`.

The receiving service verifies the token offline with `verifyDelegationToken` from `@better-iam/a2a`:

```ts
import { DelegationTokenError, verifyDelegationToken } from '@better-iam/a2a';

const verified = await verifyDelegationToken(bearer, {
  audience: 'https://api.calendar.example',
  trustedIssuers: { 'https://iam.acme.test/api/iam': 'https://iam.acme.test/a2a/jwks.json' },
  tenantId, // optional
  replay: (tokenId, expiresAt) => seenOnce(tokenId, expiresAt), // optional single use
});
// verified.personId, verified.agentId, verified.chain, verified.scopes, verified.delegationId
```

It accepts only type `biam-delegation+jwt` signed with EdDSA or ES256 by a key of the trusted issuer the token names.
It checks the audience, the organization and the times (30 seconds of clock tolerance), and a lifetime of at most an
hour. Failures throw `DelegationTokenError` with a `reason`: `type`, `issuer`, `untrusted-key`, `signature`,
`audience`, `tenant`, `expired`, `not-yet-valid`, `lifetime`, `malformed`, `replay` or `fetch`. Offline checks cannot
see a revocation until the token expires, which is why tokens are short-lived. A service running next to the deployment
can call `iam.a2a.verifyDelegationToken(token, { audience, live: true, replay })` instead. With `live` it re-checks
everything the token stands on:

- the delegation chain, the person and every agent are still in good standing;
- the acting agent's API key still exists and the agent still accepts delegation;
- the audience is still in every agent's `tokenAudiences`;
- every scope is still allowed by the current limits.

It refuses with `DELEGATION_TOKEN_INVALID`.

On the agent side, `createDelegationTokenCache({ issue })` from `@better-iam/a2a` keeps one current token per audience
and scopes. It asks for a new one only when the current one nears its end.

### What did the agent do?

`delegations.activity` shows the person everything that happened under a delegation, newest first: its lifecycle
(grant, request, approval, sessions opened, confirmations, revocation) and every allowed or denied action of the agent's
sessions acting for them. `agents.activity` shows the sponsor (or an administrator with `iam:agents:read`) everything an
agent did, with its own keys and for anyone it acted for.

```ts
const trail = await iam.api.delegations.activity(aliceSession, {
  tenantId,
  delegationId,
  limit: 50,
});
```

## Policies for agents

```json
{
  "version": 1,
  "statements": [
    {
      "sid": "NoAgentsInBilling",
      "effect": "deny",
      "actions": ["billing:*"],
      "resources": ["*"],
      "conditions": { "Bool": { "principal.delegated": true } }
    },
    {
      "sid": "AgentsNeverDelete",
      "effect": "deny",
      "actions": ["documents:delete"],
      "resources": ["*"],
      "conditions": { "StringEquals": { "principal.kind": "agent" } }
    },
    {
      "sid": "ReviewedModelsMayWrite",
      "effect": "allow",
      "actions": ["documents:write"],
      "resources": ["document/*"],
      "conditions": { "StringEquals": { "principal.agentModel": "claude-opus-5-5" } }
    }
  ]
}
```

`principal.agentId`, `principal.agentSponsorId`, `principal.agentModel`, `principal.agentProvider`,
`principal.delegationId` and `principal.delegationChain` are optional keys: absent when no agent is involved. Guard
deny statements that use them with `Exists`, as the policy linter suggests. Providers are stored in lowercase, so
compare `principal.agentProvider` with lowercase values. In a delegated session `principal.kind` is the person's
(`user`) and `principal.mfa`, `principal.owner` and `principal.rootAdmin` are always false: test `principal.delegated`
to single out agents acting for people.

## Audit

Every audit event recorded for a delegated session names the person as the actor and carries `agentId` and
`delegationId` in its `sessionContext`, covered by the audit hash chain. Agent lifecycle events are `agent:create`,
`agent:suspend`, `agent:resume`, `agent:sponsor-change`, and `agent:card-sign`; delegations record `delegation:grant`,
`delegation:request`, `delegation:approve`, `delegation:deny`, `delegation:assume`, `delegation:handoff`,
`delegation:token-issue`, `delegation:revoke`, `delegation:confirmation-request`, `delegation:confirm`, and
`delegation:reject`.
`sts.getCallerIdentity` shows `agentId` and `delegationId` for delegated sessions.

Access analysis (`analysis.findings`) reports agents without an active sponsor (`agent-without-sponsor`, high), agents
with full administrator access (`agent-admin`, high), delegable agents without a ceiling (`unbounded-agent`, low),
delegations that allow every action (`broad-delegation`, medium), active delegations unused for the dormant window
(`unused-delegation`, low), delegations that let the agent hand work on to any agent (`open-handoff`, medium when more
than one level deep, else low), and agents refused 20 or more times in the last day, with their own keys or acting
for people (`agent-denials`, medium): a sign of an agent looping or following instructions injected into what it
reads.

## Frameworks

The framework integrations pass delegated sessions through like any other credential. In `@better-iam/next`,
`apiRoute` principals carry `session.kind: 'delegated'` with `session.agentId` and `session.delegationId`, and an
agent's own key shows `identity.kind: 'agent'`.

`@better-iam/react` has hooks for your own consent screens: `useDelegations` (the agents acting or asking to act for the
signed-in person, with `grant`, `approve`, `deny`, `revoke`), `useConfirmations` (actions waiting for the person's
confirmation, with `approve` and `reject`), `useAgentCatalog`, and `useModels` (the AI models the caller may use).

```tsx
function AgentInbox({ tenantId }: { tenantId: string }) {
  const { requests, approve, deny } = useDelegations({ tenantId });
  const { pending, approve: confirm, reject } = useConfirmations({ tenantId });
  return (
    <>
      {requests.map((request) => (
        <Request
          key={request.id}
          request={request}
          onApprove={() => approve(request.id)}
          onDeny={() => deny(request.id)}
        />
      ))}
      {pending.map((item) => (
        <Confirm
          key={item.id}
          item={item}
          onApprove={() => confirm(item.id)}
          onReject={() => reject(item.id)}
        />
      ))}
    </>
  );
}
```

## MCP servers

`@better-iam/mcp` (also `better-iam/mcp`) puts tool-level authorization in front of any Model Context Protocol server
that speaks Streamable HTTP. The gate authenticates the caller, answers unauthenticated requests with a
`WWW-Authenticate` challenge naming the server's protected resource metadata (RFC 9728, served by the gate), refuses
`tools/call` requests the caller may not make (as an MCP tool error, so the model sees it), and removes the tools the
caller may not use from `tools/list` answers, in JSON and in event streams.

```ts
import { createMcpGate } from 'better-iam/mcp';

const gate = createMcpGate({
  iam, // betterIam() instance
  tenantId, // the organization that runs this server: decisions are made there (required)
  tools: {
    search_tickets: { action: 'tickets:read', resource: { type: 'ticket', id: 'index' } },
    close_ticket: {
      action: 'tickets:update',
      resource: (args) => ({ type: 'ticket', id: String(args.id) }),
      listAs: { type: 'ticket', id: 'any' },
      scopes: ['tickets.write'], // for OAuth callers
    },
    ping: { public: true },
  },
  unlisted: 'deny', // tools without a rule are hidden and refused
  oauth: resourceGuard.verifier, // optional: also accept OAuth access tokens from @better-iam/oauth
  metadata: {
    resource: 'https://mcp.acme.test/mcp',
    authorizationServers: ['https://iam.acme.test/oauth'],
  },
});

export default {
  fetch: (request: Request) =>
    gate(request, (forwarded, caller) => mcpServer.handle(forwarded, caller)),
};
```

Better IAM credentials are decided by the policy engine in `tenantId` (`action` on `resource`): a person's session, a
service account or agent key, or a delegated session in which an agent acts for a person. Deciding in the gate's own
organization matters: in each caller's tenant, any organization could grant itself access. OAuth access tokens are
decided by the tool's `scopes`, and tokens issued for another tenant are refused. The second argument of `next` tells
the server who called (`identityId`, `agentId`, `delegationId`, or the OAuth client and subject). Denied calls are
audited by the IAM server like any denied decision.

When an agent acting for a person calls a tool whose action the person confirms one call at a time, the gate files the
confirmation request for it and answers with a tool error that tells the model to call again after the approval (the
request id is in `_meta['better-iam/confirmationId']`), so agents built on any MCP client get the human-in-the-loop
flow without extra code. `confirmations: false` turns this off.

`createMcpAuthorizer` offers the same decisions (`authenticate`, `canCall`, `visibleTools`) for tool handlers written
directly against an MCP SDK.

## Agent-to-agent (A2A)

Agents that speak the [Agent2Agent protocol](https://a2a-protocol.org) describe themselves with an agent card at
`/.well-known/agent-card.json`. Better IAM can vouch for that card, and `@better-iam/a2a` (also `better-iam/a2a`)
checks other agents' cards and authorizes calls to your own A2A server.

### Attested agent cards

Give the deployment card-signing keys of their own (not the `sts.jwt` session keys) and publish their public half:

```ts
const iam = betterIam({
  // ...
  a2a: {
    signingKeys: [cardJwk], // Ed25519 (EdDSA) or P-256 (ES256) private JWK with a kid
    jwksUrl: 'https://iam.acme.test/a2a/jwks.json', // carried as jku in each signature
    cardLifetimeSeconds: 3600, // 300 to 604800
  },
});
// Route GET https://iam.acme.test/a2a/jwks.json to iam.a2a.jwksResponse().
```

`agents.signCard({ tenantId, agentId, card })` signs a card for an agent in good standing that has a registered `url`.
The card's `url` and every `additionalInterfaces[].url` (and A2A 1.0 `supportedInterfaces[].url`) must be on that
origin, so a card can only describe endpoints the organization registered for the agent. IAM sets `provider` to the
tenant's name at that origin and drops any attestation already in the card. It then adds its own extension,
`urn:better-iam:a2a:attestation:v1`, whose params name the issuer, tenant, organization, agent id and name,
`sponsored: true`, `delegable`, the model, provider and protocols, and `issuedAt`/`expiresAt`. Finally it signs the
canonical card (RFC 8785 JSON canonicalization, without `signatures`) as a detached JWS with `alg`, `kid`,
`typ: 'JOSE'` and `jku`.

The agent may call `signCard` itself with its own unscoped API key, so its A2A server can keep its card fresh. The
sponsor (in their own session) and administrators with `iam:agents:update` may call it too. Each signature is audited as
`agent:card-sign`. Because an attestation expires, suspending the agent, losing its sponsor or deleting it stops new
cards at once, and old ones expire within the card lifetime.

```ts
import { createA2aGate, createCardAttestor } from 'better-iam/a2a';

const card = createCardAttestor({
  card: {
    name: 'Triage',
    url: 'https://triage.acme.test/a2a',
    skills: [
      /* ... */
    ],
  },
  sign: (card) => iam.api.agents.signCard({ token: agentKey }, { tenantId, agentId, card }),
});
```

### The agent directory

Every card an agent has signed is also its entry in the organization's directory. `agents.directory` lists the current
attested cards of the tenant's agents in good standing, optionally only those offering a `skill` (by skill id or tag)
or speaking a `protocol`. Any credential of the tenant can read it: a person, an agent's key, or an agent acting for
someone looking for a helper to hand work to. Entries leave the directory when their attestation expires or the agent
is suspended or deleted. Each entry's `card` is the signed card itself, ready for `verifyAgentCard`.

```ts
const [translator] = await iam.api.agents.directory(delegatedSession, {
  tenantId,
  skill: 'translate',
});
```

### Checking other agents

```ts
import { discoverAgent } from 'better-iam/a2a';

const { card, attestation } = await discoverAgent('https://triage.acme.test', {
  trustedIssuers: { 'https://iam.acme.test/api/iam': 'https://iam.acme.test/a2a/jwks.json' },
  tenantId, // optional: only agents of this organization
});
```

`verifyAgentCard(card, options)` accepts a card only when one of its signatures verifies with a trusted key. With
`trustedIssuers` (attestation issuer → JWKS URL or JWKS), the card is checked only with the keys of the issuer it names,
so one trusted deployment cannot vouch in another's name. For a single deployment, `keys` (a JWKS such as
`iam.a2a.jwks()`, or a function of `kid` and `jku`) or `trustedJwksUrls` (a signature's `jku` must be listed) are
simpler. Fetched key sets are fetched again when a signature names a key they lack. The card must carry exactly one
attestation, it must be
neither expired nor issued in the future, and it must match `issuers`, `tenantId` and `origin` when those are given.
`discoverAgent` fetches the card without following redirects, with a 256 KiB limit and a 5 second timeout, and requires
the card's `url` to be on the origin it came from. Failures throw `AgentCardError`, whose `reason` is `untrusted-key`,
`signature`, `expired`, `tenant`, `endpoint`, and so on.

### Authorizing an A2A server

```ts
const gate = createA2aGate({
  iam,
  tenantId, // the organization that runs this agent: decisions are made there (required)
  card, // served at /.well-known/agent-card.json without authentication
  message: { action: 'triage:use', resource: { type: 'agent', id: 'triage' } },
  skills: {
    summarize: { action: 'triage:use', scopes: ['triage'] },
    escalate: { action: 'tickets:escalate', resource: { type: 'queue', id: 'support' } },
  },
  taskAdminAction: 'triage:operate',
});
```

- Every request other than the card needs a Better IAM credential or, with `oauth`, an access token that is decided by
  each rule's `scopes`. Decisions are made in `tenantId`. Only JSON-RPC over POST reaches the server (other HTTP methods
  answer 405 unless `otherHttpMethods: 'allow'`), and bodies are passed on exactly as the gate parsed them.
- `message/send` and `message/stream` are decided by the skill the message names (`metadata.skillId`) or by the
  `message` rule. A refused message answers JSON-RPC error `-32050` (`A2A_ACCESS_DENIED`, HTTP 403) and never reaches
  the server. A request naming two different skills is refused (`AMBIGUOUS_SKILL`).
- A task belongs to the caller who started it: the same person through the same agent, or the same OAuth client and
  subject. `tasks/get`, `tasks/cancel`, `tasks/resubscribe`, push-notification settings, and messages that continue a
  task or list it in `referenceTaskIds` answer `-32001` "task not found" to anyone else, except callers allowed
  `taskAdminAction`. Conversations (`contextId`) are private the same way: a context the caller did not start is refused
  (`-32602`). Owners are kept in memory unless you pass a shared `tasks` store.
- `agent/getAuthenticatedExtendedCard` lists only the skills the caller may use.
- An agent acting for a person whose delegation holds the action back for confirmation gets `-32051`
  (`A2A_CONFIRMATION_REQUESTED`) with `error.data.confirmationId`. The person has been asked, and the retry passes once
  they approve.

## Paying for models

Agents often call AI models. The [inference guide](inference.md) covers model access policies, budgets that cap an
agent across everything it does (including on people's behalf), and a gateway that keeps provider keys away from
agents entirely.
