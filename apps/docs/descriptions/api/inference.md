# inference

Decides which people, service accounts, and AI agents may call which AI models, caps what they spend, and meters every
call. Administrators register upstream providers (whose API keys are sealed and never returned), publish models under
public names, and set budgets. Calling a model is an ordinary policy decision, `inference:invoke` on `model/{name}`, so
roles, conditions, boundaries, and [delegations](/docs/reference/api/delegations) apply as everywhere else. Callers
reach models through the gateway `iam.inference.gateway()` builds, which keeps provider keys on the server, or through
an external gateway that uses `check` and `record`. The group needs the `inference` server option; without it every
method fails with `FEATURE_DISABLED`. The repository guide is `docs/inference.md`.

## Permissions

| Action | Allows |
| --- | --- |
| `inference:invoke` on `model/{name}` | Calling a model. |
| `inference:use-tool` on `model-tool/{kind}` | A tool the provider runs itself, for models whose `providerTools` is `policy`. |
| `iam:inference:manage` | Managing providers, models, and budgets. |
| `iam:inference:read` | Listing providers, models, and budgets, and reading usage reports. |
| `iam:inference:record` | Metering calls made for others with check tickets (external gateways). |

The `iam:*` actions are checked on the tenant, except that provider changes and budget deletion are checked on
`iam/{providerId}` and `iam/{budgetId}`. `check`, `listMine`, and `myUsage` need no `iam:*` permission: any credential
may call them for itself.

## Models, inheritance, and policies

Models are published per tenant and inherited by sub-tenants: a platform defines providers and models once at the
root tenant and every organization sees them, while an organization's own model of the same name takes precedence for
it. Conditions can use a model's attributes: `resource.provider` (the provider's name), `resource.providerKind`,
`resource.upstreamModel`, `resource.family`, `resource.tier`, `resource.contextWindow`, `resource.inputPricePerMTok`,
`resource.outputPricePerMTok`, and `resource.enabled`.

```json
{
  "effect": "allow",
  "actions": ["inference:invoke"],
  "resources": ["model/*"],
  "conditions": { "StringEquals": { "resource.tier": "small" } }
}
```

Tools the provider runs itself (web search, code execution, file search, image generation, computer use, remote MCP
servers) follow the model's `providerTools`:

- `allow` (the default) passes them.
- `deny` refuses any request that asks for one.
- `policy` decides each one as `inference:use-tool` on `model-tool/{kind}`, such as `model-tool/web_search` or
  `model-tool/mcp:kb.acme.com`, with `resource.kind` and `resource.host`.

A Responses `prompt` (a stored template that may bring its own tools) counts as the tool `prompt`, and an MCP server
URL that is not in plain canonical form reads as `mcp:invalid`. Functions the caller runs itself are never checked. A
refusal has the reason `TOOL_NOT_ALLOWED` and names the tool.

## Budgets and metering

A budget caps tokens (`maxTokens`), cost (`maxCostUsd`), calls (`maxRequests`), or any combination per `minute`,
`hour`, `day`, or `month`, in UTC windows; a `minute` budget is a requests- or tokens-per-minute rate limit.
`subjectType` says whom it covers: `tenant` (every call in the tenant), `group` (the group's members), or `identity`
(one identity; for an agent, everything it does, with its own key and in every delegated session). `scope: 'shared'`
makes one pool for everyone covered, and `scope: 'each'` gives every covered identity the full amount (identity budgets
are always shared). `models` limits a budget to some model name patterns.

A call is refused with the reason `BUDGET_EXCEEDED` when a covering budget is spent or the call's estimate would not
fit in what is left. The first refusal in a window is audited as `inference:budget-exceeded`, and crossing a budget's
`alertAtPercent` is audited once per window as `inference:budget-alert`. Cost is metered in micro-dollars: tokens times
the model's price per million tokens, with cache reads at `cachedInputPricePerMTok` when set and cache writes at the
input price. Budgets count input, output, and cache tokens. Usage records are kept for the `usageRetentionDays` option
(90 days by default) and budget counters for 35 days after their window; the expiry sweep
([`sweepExpired`](/docs/reference/api#sweepexpired)) deletes them after that.

## Gateway and server runtime

`iam.inference` is the server-side half, outside the `api` groups:

- `iam.inference.gateway(options)` returns an HTTP handler (a `Request` to `Response` function). It serves Anthropic
  Messages (`POST /v1/messages`) and token counting (`POST /v1/messages/count_tokens`, checked but not metered). It
  serves OpenAI Chat Completions (`POST /v1/chat/completions`), Responses (`POST /v1/responses`) and Embeddings
  (`POST /v1/embeddings`), and `GET /v1/models`. Callers send any Better IAM credential as the API key
  (`Authorization: Bearer` or `x-api-key`). For each call the gateway checks `inference:invoke`, the budgets and the
  provider-run tools the request asks for. It replaces the public model name with the upstream one, calls the provider
  with the sealed key, streams the answer back unchanged, and meters the tokens the provider reports. Refusals use each
  API's own error format:
  - 401;
  - 403 (`ACCESS_DENIED`, `MODEL_DISABLED`, `TOOL_NOT_ALLOWED`);
  - 404, including `RESPONSE_NOT_FOUND` for a `previous_response_id` the caller did not create;
  - 413 for a body over `maxBodyBytes`;
  - 429 (`BUDGET_EXCEEDED`, with `Retry-After` until the window resets);
  - 400 when a model is called in the other provider's format, for more than 256 tools or 64 MCP servers, and
    `UNSUPPORTED_PARAMETER` for `conversation` or `background` on `/v1/responses` and for references to objects
    stored at the provider (`item_reference` inputs, `file_id`s, Anthropic `file` sources, existing containers);
  - 502 when the provider cannot be reached.

  Options: `basePath`, `fetch`, `timeoutMs` (10 minutes), `anthropicVersion`, `maxBodyBytes` (20 MiB), and `onError`.
- `iam.inference.authorize(credential, { model, tools })` runs the same check for code that calls providers itself and
  returns either a permit with the opened provider key (never send it to a client) or `{ denied }`.
- `iam.inference.record(permit, usage)` meters a call made under a permit.
- `iam.inference.models(credential)` lists the models a credential may use, like `listMine`.

```ts
const gateway = iam.inference.gateway({ basePath: '/ai' });
// Hono: app.all('/ai/*', (c) => gateway(c.req.raw));
// Clients: new Anthropic({ baseURL: 'https://app.example.com/ai', apiKey: betterIamToken })
```

## check

Tells the caller whether they may invoke a model now and, when they may, returns a single-use ticket for an external gateway.

- **Permission:** None: any credential, for itself. The model decision is `inference:invoke` on `model/{name}`.
- **Audited as:** Denials as `inference:invoke` with outcome `deny`, like any decision; the first budget refusal in a
  window as `inference:budget-exceeded`.
- **Errors:** `NOT_FOUND` for a model the tenant cannot see; `INVALID_INPUT` for a malformed model name, an
  `estimatedTokens` outside 0 to 100 000 000, or `tools` that are not at most 64 provider tool ids;
  `FEATURE_DISABLED` without the `inference` option.

The answer is `{ allowed: true, model, budgets, ticket }`, or `{ allowed: false, reason, model }`. The `reason` is one
of:

- `ACCESS_DENIED`;
- `MODEL_DISABLED`: the model or its provider is off;
- `TOOL_NOT_ALLOWED`: with the refused `tool`, when the model's `providerTools` does not allow one of `tools`;
- `BUDGET_EXCEEDED`: with the exhausted `budget`'s standing.

`tools` lists the provider-run tools the call will ask for, as ids such as `web_search` or `mcp:kb.acme.com`
(`providerToolsOf` from `better-iam` reads them from a request body). `estimatedTokens`, priced at the model's input
price, must fit in every covering budget. The
`ticket` is valid for one hour and names the caller, their session, and the model: an external gateway makes the call
and then redeems it with `record`.

```ts
const result = await iam.api.inference.check(credential, { tenantId, model: 'opus', estimatedTokens: 4_000 });
if (!result.allowed) return refuse(result.reason);
// Call the provider, then report the tokens with result.ticket through inference.record.
```

## createModel

Publishes a model under a public name, served by a provider of this tenant or an ancestor.

- **Permission:** `iam:inference:manage` on the tenant.
- **Audited as:** `iam:inference:manage`.
- **Errors:** `CONFLICT` (409) when this tenant already has a model of that name; `NOT_FOUND` when the provider is not
  this tenant's or an ancestor's; `INVALID_INPUT` for a malformed name, a `family` or `tier` that is not a short
  identifier, a `contextWindow` or `maxOutputTokens` outside 1 to 100 000 000, a price outside 0 to 10 000,
  `fallbacks` naming more than five models or the model itself, or a `providerTools` other than `allow`, `deny`, or
  `policy`.

The `name` (1 to 128 letters, digits, or `._:/@+-`, starting with a letter or digit) is what callers send and what
policies name as `model/{name}`; `upstreamModel` is the provider's own name for it. Prices are US dollars per million
tokens and drive cost metering and cost budgets; a model without prices costs nothing. `tier` and `family` are
free-form attributes for policies. `maxOutputTokens` caps the output of every gateway call. `fallbacks` lists models
the gateway tries, in order, when this one's provider cannot be reached or answers 429, 500, 502, 503, 504, or 529;
each one only if the caller may call it and it speaks the same wire format. `providerTools` (`allow` by default,
`deny`, or `policy`) governs the tools the provider runs itself (see
[Models, inheritance, and policies](#models-inheritance-and-policies)). A new model starts enabled, and sub-tenants
inherit it.

```ts
await iam.api.inference.createModel(credential, {
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

## createProvider

Registers an upstream model provider account, whose API key is sealed and never returned.

- **Permission:** `iam:inference:manage` on the tenant, and a recent sign-in.
- **Audited as:** `iam:inference:manage`.
- **Errors:** `CONFLICT` (409) for a name another provider of the tenant uses (ignoring case); `ACCESS_DENIED` for a
  custom `baseUrl` from anyone but a root administrator, unless the deployment sets `inference.allowCustomBaseUrls`;
  `INVALID_INPUT` for an unknown `kind`, an `openai-compatible` provider without `baseUrl`, an `apiKey` that is not 8
  to 4096 characters without whitespace, or a `baseUrl` that is not https or carries credentials, a query, or a
  fragment; `RECENT_AUTH_REQUIRED` without a recent sign-in.

`kind` is `anthropic`, `openai`, or `openai-compatible` (any endpoint that speaks the OpenAI Chat Completions API).
The first two default to the provider's public endpoint. A custom base URL makes the gateway send the key to that
address, hence the root rule. The key is sealed with the deployment secret, bound to this provider, and opened only
inside the server; the result shows `keyHint`, its last four characters. Models of this tenant and its sub-tenants may
use the provider. [`rotateSecrets`](/docs/reference/api#rotatesecrets) re-seals provider keys under a new secret.

```ts
const anthropic = await iam.api.inference.createProvider(credential, {
  tenantId,
  name: 'Anthropic',
  kind: 'anthropic',
  apiKey: process.env.ANTHROPIC_API_KEY!,
});
```

## deleteBudget

Deletes a budget together with its usage counters.

- **Permission:** `iam:inference:manage` on the budget.
- **Audited as:** `iam:inference:manage`.
- **Errors:** `NOT_FOUND` when the budget is not in this tenant.

Calls it covered are no longer capped by it. Usage records are kept, so reports still show the spending.

## deleteModel

Removes one of this tenant's models; an inherited model of the same name becomes visible again.

- **Permission:** `iam:inference:manage` on the tenant.
- **Audited as:** `iam:inference:manage`.
- **Errors:** `NOT_FOUND` when this tenant defines no model of that name (an inherited model is deleted in the tenant
  that defines it).

Callers asking for the name afterwards get `NOT_FOUND` unless an ancestor defines it. To stop calls without deleting,
use `updateModel` with `enabled: false`.

## deleteProvider

Deletes a provider that no model uses, together with its sealed key.

- **Permission:** `iam:inference:manage` on the provider.
- **Audited as:** `iam:inference:manage`.
- **Errors:** `RESOURCE_IN_USE` (409) while any model uses it, a sub-tenant's included; `NOT_FOUND` when the provider
  is not this tenant's own.

Point the models at another provider with `updateModel`, or delete them, first.

## listBudgets

Lists the tenant's budgets by name, with the current window's standing of each shared pool.

- **Permission:** `iam:inference:read` on the tenant.
- **Audited as:** `iam:inference:read`.

Each budget carries `maxCostUsd` next to the stored `maxCostMicros`, `subjectName` (the group's name, or the
identity's email or name), and, for `shared` and `identity` budgets, `standing`: the window's start, `resetsAt`, and
the tokens and cost used and remaining. An `each` budget has one pool per identity; people see theirs with `myUsage`.

## listMine

Lists the enabled models the caller may invoke, for a model picker.

- **Permission:** None: any credential, for itself.
- **Audited as:** Not audited; the decisions are evaluated without being recorded.
- **Errors:** `FEATURE_DISABLED` without the `inference` option.

Each model is decided like an `inference:invoke` call, so a delegated agent session sees only what the person may use
within the delegation. Budgets are not considered; `check` does that before a call.

## listModels

Lists every model the tenant can see, its own and inherited ones, by name.

- **Permission:** `iam:inference:read` on the tenant.
- **Audited as:** `iam:inference:read`.

When a tenant and an ancestor define the same name, only the nearest definition appears. `inherited` marks models an
ancestor defines, and `enabled` is false when the model is disabled or its provider is gone. `provider` names the
provider and its kind; keys never appear.

## listProviders

Lists the providers this tenant's models may use: its own, then its ancestors'.

- **Permission:** `iam:inference:read` on the tenant.
- **Audited as:** `iam:inference:read`.

The tenant's own providers come first (`inherited: false`), each group sorted by name. Each shows `kind`, `baseUrl`,
`keyHint` (the key's last four characters), and `keyRotatedAt`, when the key was last replaced.

## myUsage

Returns the caller's own usage by model and the standing of every budget that covers them.

- **Permission:** None: any credential, for itself, in its own tenant.
- **Audited as:** Not audited; it only reads.
- **Errors:** `ACCESS_DENIED` when `tenantId` is not the credential's own tenant; `INVALID_INPUT` when `from` is after
  `to`.

The report covers `from` (by default the start of this month, UTC) to `to` (by default now). `budgets` lists the
standing of every budget that covers the caller for a model they used in that range or can see, so people can check
what is left of an allowance before they run out.

## record

Meters a call an external gateway made after `check`, by redeeming the check's ticket.

- **Permission:** `iam:inference:record` on the tenant, typically held by the gateway's service account.
- **Audited as:** `iam:inference:record`; crossing a budget's `alertAtPercent` also as `inference:budget-alert`.
- **Errors:** `INVALID_TICKET` (400) for an unknown, used, expired, or other-tenant ticket; `INVALID_INPUT` for a token
  count outside 0 to 100 000 000.

The ticket supplies the caller as the check saw them (their identity, and the agent and delegation behind a delegated
session) and the model; the gateway reports the token counts from the provider's response (`inputTokens`,
`outputTokens`, and optionally `cacheReadTokens` and `cacheWriteTokens`), plus `status` (`error` for a failed call),
`requestId`, and `latencyMs`. The usage is attributed to that caller and added to every covering budget and delegation
spending cap, even when the caller's session has ended since the check, so a short session cannot make an allowed call
escape its budgets. Each ticket works once. The result is
`{ recorded: true, costMicros }`.

```ts
await iam.api.inference.record(gatewayKey, {
  tenantId,
  ticket: result.ticket,
  inputTokens: response.usage.input_tokens,
  outputTokens: response.usage.output_tokens,
});
```

## setBudget

Creates a budget, or replaces one when `budgetId` is given.

- **Permission:** `iam:inference:manage` on the tenant.
- **Audited as:** `iam:inference:manage`.
- **Errors:** `CONFLICT` (409) for a name another budget of the tenant uses (ignoring case); `NOT_FOUND` for a group
  or identity that is not in this tenant (or a deleted identity), or a `budgetId` that is not; `INVALID_INPUT` without
  any of `maxTokens`, `maxCostUsd` and `maxRequests`, for a `maxCostUsd` that is not above 0 or is above 10 000, a
  `maxTokens` or `maxRequests` below 1, an `alertAtPercent` outside 1 to 100, or a malformed model pattern.

`subjectId` names the group or identity; a `tenant` budget covers the tenant itself. `maxRequests` caps the number of
calls per window, a rate limit for agents that loop. With `budgetId`, fields you leave out keep their stored values,
and `null` clears `maxTokens`, `maxCostUsd`, `maxRequests`, `models`, or `alertAtPercent`. `alertAtPercent` audits
`inference:budget-alert` once per window when usage crosses that share of any limit.

```ts
// Every person gets a million tokens a day.
await iam.api.inference.setBudget(credential, {
  tenantId,
  name: 'Daily per person',
  subjectType: 'tenant',
  scope: 'each',
  period: 'day',
  maxTokens: 1_000_000,
  alertAtPercent: 80,
});
// One agent, across its own key and every delegated session.
await iam.api.inference.setBudget(credential, {
  tenantId,
  name: 'Triage agent',
  subjectType: 'identity',
  subjectId: agentId,
  period: 'month',
  maxCostUsd: 200,
});
```

## updateModel

Changes one of this tenant's models, found by its name.

- **Permission:** `iam:inference:manage` on the tenant.
- **Audited as:** `iam:inference:manage`.
- **Errors:** `NOT_FOUND` when this tenant defines no model of that name or the new provider is not visible to it;
  `INVALID_INPUT` as for `createModel`.

Fields you leave out keep their values, and `null` clears an optional one. `enabled: false` stops every call to the
model at once (checks answer `MODEL_DISABLED`); new prices apply to calls metered from then on. The name cannot change.
An inherited model changes only in the tenant that defines it; a sub-tenant publishes its own model of the same name
instead.

## updateProvider

Renames a provider, moves its base URL, or replaces its API key.

- **Permission:** `iam:inference:manage` on the provider, and a recent sign-in.
- **Audited as:** `iam:inference:manage`.
- **Errors:** `NOT_FOUND` when the provider is not this tenant's own; `CONFLICT` (409) for a name another provider
  uses; `ACCESS_DENIED` and `INVALID_INPUT` for `baseUrl` and `apiKey` as in `createProvider`;
  `RECENT_AUTH_REQUIRED` without a recent sign-in.

A new `apiKey` is sealed like the first one and updates `keyHint` and `keyRotatedAt`; the next call through the
gateway uses it.

## usage

Reports model calls between two times, grouped by identity, agent, model, or day.

- **Permission:** `iam:inference:read` on the tenant.
- **Audited as:** `iam:inference:read`.
- **Errors:** `INVALID_INPUT` for an unknown `groupBy` or a `from` after `to`.

`from` defaults to the start of this month (UTC) and `to` to now; `identityId`, `agentId`, and `model` narrow the
records, and `groupBy` defaults to `model`. Each row counts requests, errors, input, output, and cache tokens, and cost
(`costMicros` and `costUsd`), largest cost first, with a `label` (email or name) when grouped by identity or agent;
`totals` adds them up. A call an agent made for a person counts under the person by identity and under the agent by
agent.

```ts
const report = await iam.api.inference.usage(credential, { tenantId, groupBy: 'agent' });
```
