# Inference access control

Better IAM decides who may call which AI models, how much they may spend, and keeps a record of every call. It works
for people, service accounts, and [AI agents](agents.md), including agents acting on a person's behalf. Enable it
with the `inference` option:

```ts
const iam = betterIam({
  // ...
  inference: {
    usageRetentionDays: 90, // per-call usage records (1 to 3650)
    allowCustomBaseUrls: false, // only root administrators may point providers at custom URLs
  },
});
```

The option adds a resource type, `model`, and an action, `inference:invoke`, to the permission catalog; the
`inference` API group; and `iam.inference`, the server-side runtime with the gateway.

## Providers

A provider is an upstream account: `anthropic`, `openai`, or `openai-compatible` (any endpoint that speaks the OpenAI
Chat Completions API, such as vLLM or a router). Its API key is sealed with the deployment secret, never returned, and
opened only inside the server when the gateway calls the provider. Administrators see the key's last four characters.

```ts
const anthropic = await iam.api.inference.createProvider(admin, {
  tenantId,
  name: 'Anthropic',
  kind: 'anthropic',
  apiKey: process.env.ANTHROPIC_API_KEY!,
});
```

A custom `baseUrl` (required for `openai-compatible`) makes the gateway send the key to that address, so only a root
administrator may set one unless the deployment sets `inference.allowCustomBaseUrls`. URLs must be https. Replace a key
with `updateProvider({ apiKey })`; creating and updating providers needs a recent sign-in. `rotateSecrets()` re-seals
provider keys with the new deployment secret.

## Models

A model is published under a public name that callers use and policies name (`model/{name}`). It is served by a
provider of the same tenant or an ancestor, as the provider's own `upstreamModel`.

```ts
await iam.api.inference.createModel(admin, {
  tenantId,
  name: 'opus',
  providerId: anthropic.id,
  upstreamModel: 'claude-opus-5-5',
  tier: 'frontier',
  family: 'claude',
  inputPricePerMTok: 5,
  outputPricePerMTok: 25,
  cachedInputPricePerMTok: 0.5,
});
```

Models are inherited: a platform defines providers and models once at the root tenant and every organization sees
them. An organization may publish its own model under the same name, which takes precedence for it. `enabled: false`
stops every call at once. `maxOutputTokens` caps the output of every call through the gateway.

`fallbacks` (up to five model names, in order) keeps calls going when a provider has trouble. When the model's provider
cannot be reached or answers 429, 500, 502, 503, 504, or 529 (overloaded), the gateway tries the next fallback. Each
fallback is used only if the caller may call it (access and budgets are checked like any call) and it speaks the same
wire format. The failed attempt is metered with no tokens against the first model and the answer against the model
that served it. Responses name that model in `x-better-iam-model`, and `x-better-iam-fallback-from` names the model
asked for.

```ts
await iam.api.inference.updateModel(admin, {
  tenantId,
  name: 'opus',
  fallbacks: ['opus-eu', 'sonnet'],
});
```

## Who may call which model

Model access is an ordinary policy decision: `inference:invoke` on `model/{name}`. Model attributes are available to
conditions as `resource.provider`, `resource.providerKind`, `resource.upstreamModel`, `resource.tier`,
`resource.family`, `resource.contextWindow`, `resource.inputPricePerMTok`, `resource.outputPricePerMTok`, and
`resource.enabled`. `resource.provider` is the provider's display name (such as `Anthropic`); match the API family with
`resource.providerKind` (`anthropic`, `openai`, `openai-compatible`).

```json
{
  "version": 1,
  "statements": [
    {
      "effect": "allow",
      "actions": ["inference:invoke"],
      "resources": ["model/*"],
      "conditions": { "StringEquals": { "resource.tier": "small" } }
    },
    {
      "effect": "allow",
      "actions": ["inference:invoke"],
      "resources": ["model/opus"],
      "conditions": { "Bool": { "principal.mfa": true } }
    }
  ]
}
```

Agents, delegations, and every other principal key work as usual: a delegated agent session can use only the models
the person may use, within the delegation's scope. Delegated sessions never carry MFA, so a statement conditioned on
`principal.mfa` (like the second one above) never admits an agent acting for a person.

`inference.listMine` lists the enabled models the caller may use (for a model picker). `inference.check` answers
whether the caller may invoke a model now, including budgets.

### Tools the provider runs

Some tools run at the model provider, not in the caller's code: web search and web fetch, code execution and code
interpreter, file search, image generation, and remote MCP servers the provider connects to. Computer use, bash and the
text editor are defined by the provider for the model to drive. These tools can read the web, run code, or reach
outside systems with the organization's provider account. A prompt-injected agent could use them to leak data, so each
model says what it allows with `providerTools`:

- `allow` (the default): requests may ask for any of them.
- `deny`: any request that asks for one is refused.
- `policy`: each tool is an ordinary decision, `inference:use-tool` on `model-tool/{kind}`.

```ts
await iam.api.inference.updateModel(admin, {
  tenantId,
  name: 'gpt-research',
  providerTools: 'policy',
});
```

```json
{
  "effect": "allow",
  "actions": ["inference:use-tool"],
  "resources": ["model-tool/web_search", "model-tool/mcp:*.acme.com"]
}
```

The gateway reads the tools from the request:

- Anthropic `tools[].type` (anything but a custom tool), and each `mcp_servers[].url`;
- OpenAI Responses `tools[].type` (anything but `function` and `custom`);
- Chat Completions `web_search_options`.

Kinds are named without their version date or `_preview` suffix: `web_search`, `web_fetch`, `code_execution`,
`code_interpreter`, `file_search`, `image_generation`, `computer`, `bash`, `text_editor`, and so on. A remote MCP server
is `mcp:{host}` (such as `mcp:kb.acme.com`, without a trailing dot), or `mcp:{connector_id}` for an OpenAI connector.
Only a plain URL in canonical form names a host. A URL with user info, a backslash, an encoded host or a spelled-out
default port reads as `mcp:invalid`, because another parser could see a different host. A Responses `prompt` (a
template stored at the provider, which may bring tools of its own) counts as the tool `prompt`. Policies see
`resource.kind` and, for MCP servers, `resource.host`. Tools the caller runs itself (functions and custom tools) are
never checked, and token counting runs no tool. A request may list at most 256 tools and 64 MCP servers, so every one
of them is read.

A refused request answers 403 `TOOL_NOT_ALLOWED`, naming the tool, and never reaches the provider. Refusals are audited
as `inference:use-tool` denials. Delegations and agent ceilings apply as usual: an agent acting for a person needs
`inference:use-tool` within the delegation's scope. External gateways pass the tool ids to `inference.check` as
`tools`. The gateway's own reading is exported as `providerToolsOf(path, body)`.

## Budgets

A budget caps tokens (`maxTokens`), cost (`maxCostUsd`), calls (`maxRequests`, a rate limit for agents that loop), or
any combination, per `minute`, `hour`, `day`, or `month` (UTC windows). A `minute` budget is a rate limit in the usual
sense: requests or tokens per minute.

| `subjectType` | Covers                                                                                   |
| ------------- | ---------------------------------------------------------------------------------------- |
| `tenant`      | Every call made in the tenant.                                                           |
| `group`       | Calls by the group's members.                                                            |
| `identity`    | One identity. For an agent, everything it does: its own key and every delegated session. |

`scope: 'shared'` (the default) makes one pool for everyone covered; `scope: 'each'` gives every identity covered the
full amount (for example "each person 1M tokens a day"). An `identity` budget is always one pool; on a person it also
counts what agents do on their behalf. `models` limits a budget to some model name patterns. People can also cap what
an agent spends for them on a single delegation (`spend`, see
[AI agents](agents.md#capping-what-an-agent-spends-for-you)).

```ts
await iam.api.inference.setBudget(admin, {
  tenantId,
  name: 'Daily per person',
  subjectType: 'tenant',
  scope: 'each',
  period: 'day',
  maxTokens: 1_000_000,
  alertAtPercent: 80,
});
await iam.api.inference.setBudget(admin, {
  tenantId,
  name: 'Triage agent',
  subjectType: 'identity',
  subjectId: agent.id,
  period: 'month',
  maxCostUsd: 200,
});
await iam.api.inference.setBudget(admin, {
  tenantId,
  name: 'Agents: 60 requests a minute',
  subjectType: 'tenant',
  scope: 'each',
  period: 'minute',
  maxRequests: 60,
});
```

A call is refused with `BUDGET_EXCEEDED` when a covering budget is spent, or when the call's estimate would not fit in
what is left. The gateway estimates a quarter of the request's bytes plus the requested output limit (`max_tokens`,
`max_completion_tokens` or `max_output_tokens`);
`inference.check` and `iam.inference.authorize` take `estimatedTokens` (0 when left out). The first refusal in a window
is audited as `inference:budget-exceeded`; crossing `alertAtPercent` is audited once per window as
`inference:budget-alert` (subscribe a webhook to either). Cost is metered in micro-dollars: tokens times the model's
price per million tokens.

## The gateway

The gateway lets any Better IAM credential call models without ever holding a provider key. It passes each provider's
own wire format through, including streaming (only the model name is swapped, and OpenAI Chat Completions streams are
asked to report usage):

- Anthropic Messages, `POST /v1/messages`, for models on an `anthropic` provider, and token counting,
  `POST /v1/messages/count_tokens` (checked like a call but not metered, since it costs nothing);
- OpenAI Chat Completions, `POST /v1/chat/completions`, Responses, `POST /v1/responses`, and Embeddings,
  `POST /v1/embeddings`, for `openai` and `openai-compatible` providers;
- `GET /v1/models` lists the models the caller may use, in the OpenAI format (or Anthropic's when the request carries
  `anthropic-version`).

Responses API conversations are stored at the provider under the organization's key, so every caller could reach every
other caller's conversation by id. The gateway keeps them apart: it records who created each response it relays, and
`previous_response_id` must name one of the caller's own (the same person, through the same agent if an agent is
acting) at the same provider; any other answers 404 `RESPONSE_NOT_FOUND` without reaching the provider, and fallbacks
to another provider are skipped. The `conversation` parameter and `background: true` are refused with 400
`UNSUPPORTED_PARAMETER`, because their state and usage stay out of the gateway's sight. So is every other reference to
objects stored at the provider under the organization's key, which the gateway cannot tie to the caller:

- Responses `item_reference` inputs;
- `file_id`s in inputs and messages, and Anthropic `file` sources;
- an existing code-execution `container`.

Built-in tools that the provider bills apart from tokens (web search, file search, code interpreter) are not metered.

```ts
const gateway = iam.inference.gateway({ basePath: '/ai' });
// Next.js, in app/ai/[...path]/route.ts: export { gateway as GET, gateway as POST };
// Hono: app.all('/ai/*', (c) => gateway(c.req.raw));
```

Point an SDK at it with a Better IAM credential as the API key:

```ts
import Anthropic from '@anthropic-ai/sdk';
const client = new Anthropic({
  baseURL: 'https://app.example.com/ai',
  apiKey: agentKeyOrDelegatedToken,
});
await client.messages.create({
  model: 'opus',
  max_tokens: 1024,
  messages: [{ role: 'user', content: 'Hi' }],
});
```

For each request the gateway authenticates the caller (bearer token or `x-api-key`), checks `inference:invoke` and the
budgets, replaces the public model name with the upstream one, holds output to the model's `maxOutputTokens` (a larger
`max_tokens`, `max_completion_tokens` or `max_output_tokens` is lowered, and a request without one gets it; embeddings
and token counts have none), sends the request with the
sealed key, streams the answer back, and meters the tokens the provider reports (for streams, when the stream ends;
OpenAI streams get `stream_options.include_usage`). Providers report a stream's final counts last. When a stream ends
without them (the client closed it early, or the provider sent none), the gateway estimates:

- input: what the provider reported so far, else a token per four bytes of the request;
- output: a token per four generated characters seen.

So closing a stream early never makes a call free. Refusals use each API's own error shape: 401, 403 (`ACCESS_DENIED`,
`MODEL_DISABLED`, `TOOL_NOT_ALLOWED`), 404, 413 (`TOO_LARGE`), 429 (`BUDGET_EXCEEDED`, with `Retry-After` until the window resets), 400
(`WRONG_FORMAT` when a model is called in the other provider's format), or 502 (`UPSTREAM_UNAVAILABLE`); the provider's
own errors pass through with their status. Relayed responses carry `x-better-iam-request-id` and
`x-better-iam-model`.

### Other gateways

An existing gateway can use Better IAM for the decision and the metering. It calls `inference.check` with the caller's
credential, receives a single-use `ticket` (valid one hour) when the call is allowed, makes the call itself, and then
redeems the ticket with the token counts through `inference.record`, using its own service account key with
`iam:inference:record`. In-process code can use `iam.inference.authorize(credential, { model })`, which returns
`{ denied }` or a permit `{ principal, tenantId, check, upstreamModel, provider }` whose `provider` holds the opened
key (never expose it), and then `iam.inference.record(permit, usage)`. When the deployment has billing, every metered
call also lands in the spend ledger as the `inference` meter.

## Usage reports

`inference.usage` (with `iam:inference:read`) aggregates calls between `from` and `to` by `identity`, `agent`,
`model`, or `day`, with requests, errors, token counts, and cost. `inference.myUsage` shows a caller their own usage and
the standing of every budget that covers them. `inference.listBudgets` shows the current window of each shared pool.

Usage records are kept for `usageRetentionDays` and budget counters 35 days past their window; `iam.sweepExpired()`
deletes them after that.

## Permissions

| Action                 | Allows                                                                                |
| ---------------------- | ------------------------------------------------------------------------------------- |
| `inference:invoke`     | Calling a model (`model/{name}`).                                                     |
| `inference:use-tool`   | A provider-run tool, for models with `providerTools: 'policy'` (`model-tool/{kind}`). |
| `iam:inference:manage` | Providers, models, and budgets.                                                       |
| `iam:inference:read`   | Listing providers, models, and budgets; usage reports.                                |
| `iam:inference:record` | Metering calls for others with check tickets (gateways).                              |
