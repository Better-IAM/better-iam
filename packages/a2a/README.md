# @better-iam/a2a

[Agent2Agent (A2A)](https://a2a-protocol.org) support backed by Better IAM: agent cards that Better IAM signs and
attests, verification and discovery of other agents' cards, and authorization for A2A servers.

## Attested agent cards

With the `a2a` option, `agents.signCard` signs an agent's A2A card. It checks that the card's `url` and every
`additionalInterfaces[].url` (and A2A 1.0 `supportedInterfaces[].url`) is on the origin of the agent's registered
`url`. It sets `provider` to the tenant's name at that origin and adds an attestation extension
(`urn:better-iam:a2a:attestation:v1`): the agent, its organization, that a person sponsors it, its model, and when the
attestation expires. It then signs the canonical card (RFC 8785) as a detached JWS. Other agents check it with the
deployment's public card keys. The agent signs with its own unscoped API key; its sponsor and administrators with
`iam:agents:update` may sign too.

```ts
import { betterIam } from 'better-iam';
import { createA2aGate, createCardAttestor } from '@better-iam/a2a';

const iam = betterIam({
  /* ... */
  a2a: { signingKeys: [cardSigningJwk], jwksUrl: 'https://iam.example.com/a2a/jwks.json' },
});
// Serve iam.a2a.jwksResponse() at the jwksUrl.

const card = createCardAttestor({
  card: {
    name: 'Triage',
    url: 'https://triage.example.com/a2a',
    skills: [
      /* ... */
    ],
  },
  sign: (card) =>
    iam.api.agents.signCard({ token: process.env.AGENT_KEY }, { tenantId, agentId, card }),
});
```

`createCardAttestor` signs on first use, re-signs when less than a fifth of the attestation's lifetime is left, and
keeps serving the previous card if re-signing fails while it is still valid.

## Verifying other agents

```ts
import { discoverAgent, verifyAgentCard } from '@better-iam/a2a';

const { card, attestation } = await discoverAgent('https://triage.example.com', {
  trustedIssuers: { 'https://iam.example.com/api/iam': 'https://iam.example.com/a2a/jwks.json' },
  tenantId: 'acme', // optional: only agents of this organization
});
```

`verifyAgentCard(card, options)` accepts only cards signed by a trusted key. With `trustedIssuers` (attestation issuer
→ JWKS URL or JWKS) a card is checked only with the keys of the issuer it names, so one trusted deployment cannot
vouch in another's name. For a single deployment, `keys` (a JWKS, or a function of `kid` and `jku`) or
`trustedJwksUrls` (a signature's `jku` must be one of them) are simpler. Fetched key sets are cached and fetched again
when a signature names a key they lack. The card must carry exactly one attestation that is neither expired nor from
the future, and match `issuers`, `tenantId` and `origin` when given. `discoverAgent` fetches
`/.well-known/agent-card.json` with a size limit, a timeout and no redirects, and requires the card's `url` to be on the
origin it was fetched from. Failures throw `AgentCardError` with a `reason`.

## Authorizing an A2A server

```ts
const gate = createA2aGate({
  iam,
  tenantId, // the organization that runs this agent: decisions are made there (required)
  card,
  message: { action: 'triage:use', resource: { type: 'agent', id: 'triage' } },
  skills: {
    summarize: { action: 'triage:use', scopes: ['triage'] },
    escalate: { action: 'tickets:escalate', resource: { type: 'queue', id: 'support' } },
  },
  taskAdminAction: 'triage:operate',
});

export default {
  fetch: (request: Request) => gate(request, (forwarded, caller) => a2aHandler(forwarded, caller)),
};
```

- The card is served at `/.well-known/agent-card.json` (and the older `agent.json`) without authentication. Every other
  request needs a Better IAM credential (a person's session, an agent key, or a delegated session in which an agent
  acts for a person) or, with `oauth`, an access token decided by each rule's `scopes` (tokens for another tenant are
  refused). Decisions are made in `tenantId`; a function may pick it per caller or return undefined to refuse them.
- Only JSON-RPC over POST reaches the server (other HTTP methods answer 405 unless `otherHttpMethods: 'allow'`). Bodies
  are read up to `maxBodyBytes` (4 MiB) and passed on exactly as the gate parsed them.
- `message/send` and `message/stream` are decided by the skill the message names (`metadata.skillId`) or by the
  `message` rule. A refusal answers JSON-RPC error `A2A_ACCESS_DENIED` (`-32050`, HTTP 403) with `error.data.reason`.
  Skills without a rule are refused unless `unlistedSkills: 'message'`, and a request naming two different skills is
  refused (`AMBIGUOUS_SKILL`).
- Tasks belong to the caller who started them (the gate records task ids from JSON answers and event streams).
  `tasks/get`, `tasks/cancel`, `tasks/resubscribe`, push notification settings, and messages that continue a task or
  list it in `referenceTaskIds` answer "task not found" (`-32001`) to anyone else, except callers allowed
  `taskAdminAction`. Conversations (`contextId`) are private the same way: a message naming a context the caller did
  not start is refused (`-32602`). Owners are kept in memory by default (unknown tasks and contexts belong to no one,
  so a restart ends access to earlier ones); pass `tasks` (`get`/`set` by key `task:{id}` or `context:{id}`) to share
  them between instances.
- `agent/getAuthenticatedExtendedCard` lists only the skills the caller may use.
- An agent acting for a person whose delegation holds the action back for confirmation gets
  `A2A_CONFIRMATION_REQUESTED` (`-32051`) with `error.data.confirmationId`; the person was asked, and the retry passes
  once they approve.
- Other JSON-RPC methods are refused unless `otherMethods: 'allow'`; batches are refused. Unexpected errors answer
  `-32603` (HTTP 500) after `onError`.

## Handing work on to another agent

An agent acting for a person can hand part of the work to the agent it calls, when the person allows hand-offs
(`delegations.handoff`, see [AI agents](../../docs/agents.md)). The hand-off travels in the A2A message's metadata:

```ts
import { handoffOf, withHandoff } from '@better-iam/a2a';

// The calling agent, in its delegated session:
const handoff = await iam.api.delegations.handoff(delegated, {
  tenantId,
  agentId: researcherId,
  scopes: ['documents:read'],
});
await a2aClient.sendMessage({ message: withHandoff(message, handoff.id) });

// The called agent's server, with its own key:
const delegationId = handoffOf(params);
const session = delegationId
  ? await iam.api.delegations.assume({ token: researcherKey }, { tenantId, delegationId })
  : undefined; // act for the same person with session.token, within the hand-off
```

`assume` refuses a hand-off that is not the called agent's, so a forwarded id is of no use to anyone else.

## Delegation tokens for other services

Services that do not call Better IAM can still check that an agent acts for a person. The agent gets a delegation
token (`delegations.issueToken` in its delegated session): a short-lived JWT of type `biam-delegation+jwt`, signed with
the deployment's card keys. Its `sub` is the person, and its `act` names the agent, with nested `act` claims for agents
that handed the work on (RFC 8693). The service verifies it offline:

```ts
import { verifyDelegationToken } from '@better-iam/a2a';

const verified = await verifyDelegationToken(bearerToken, {
  audience: 'https://api.calendar.example',
  trustedIssuers: { 'https://iam.example.com/api/iam': 'https://iam.example.com/a2a/jwks.json' },
});
// { personId, tenantId, agentId, chain, scopes, delegationId, tokenId, expiresAt, ... }
```

Only tokens for exactly `audience`, from the trusted issuer they name, signed by one of that issuer's keys, current
and issued for at most an hour are accepted. Pass `tenantId` to accept a single organization, and `replay` to refuse a
token id seen before. Failures throw `DelegationTokenError` with a `reason`. On the agent side,
`createDelegationTokenCache({ issue })` returns `(audience, scopes?) => Promise<string>`, which reuses a token until it
nears its end.

`createA2aAuthorizer(options)` exposes the same decisions (`authenticate`, `canSend`, `visibleSkills`, `isTaskAdmin`)
for servers written directly with an A2A SDK.

See [AI agents](../../docs/agents.md) for agents, sponsors, delegation, and hand-offs between agents.

License: Apache-2.0.
