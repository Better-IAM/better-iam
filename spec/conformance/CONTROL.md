# Conformance control endpoints

A server started with `--conformance` (see [CONFIG.md](CONFIG.md)) answers, besides its normal HTTP surface, the
test-control endpoints below. The replay runner (`scripts/conformance/replay.mjs`) drives a server only through them
and the public HTTP surface, so the TypeScript, Rust and Go servers implement them identically. They must never be
reachable without `--conformance`: the path then belongs to the normal handler (which answers 404).

All endpoints live under `/__conformance/`, outside `basePath`, take and return JSON (`content-type:
application/json`), and answer HTTP 200 for every request they understood, also when the operation they ran failed
(the failure is in the body). A malformed control request is answered with its status and
`{"error": {"code", "status", "message"}}` (400 `INVALID_INPUT`, 404 `NOT_FOUND`, 405 `METHOD_NOT_ALLOWED`).

Errors inside bodies use one shape, `{"code", "status", "message", "retryAfterMs"?}`: an `IamError` gives its code,
status and message; anything else is `{"code": "INTERNAL_ERROR", "status": 500, "message": "Internal server error",
"thrown": {"name", "message"}}` (the runner compares only code and status of those).

Values that JSON cannot carry use the tagged encoding of FORMAT.md ("Value encoding"): `{"$bytes": base64}`,
`{"$date": iso}`, `{"$bigint": "…"}`, `{"$map": [[k, v]]}`, `{"$set": […]}`, `{"$undefined": true}`,
`{"$headers": {…}}`, `{"$function": name}`, `{"$error": {…}}`.

## Startup

- `GET /__conformance/ready` → `{"ready": true, "implementation": "typescript" | "rust" | "go", "conformance": 1}`
  once the instance is built and `initialize()` (migrations) has run. The runner polls it.
- A configuration the server refuses ends the process with exit status 1 and a single JSON line on stderr,
  `{"error": {"code", "status", "message"}}` (the same code and message the in-process `betterIam(options)` throws).
  Traces recorded from a failing construction check exactly this.

## Clock

The server has two clocks, and in conformance mode both are under control:

- the **injected clock**, `authentication.now` in TypeScript: the time sessions, challenges, lifetimes, rate limits
  and most records are stamped with;
- the **wall clock**, `Date.now()` in TypeScript (`SystemTime::now` / `time.Now` in the ports): what the modules that
  read real time directly use (the TypeScript server does in about 150 places, such as tenant `createdAt`, audit event
  timestamps, health latency). Ports read the wall clock wherever the TypeScript source reads `Date.now()` and the
  injected clock wherever it calls `ctx.now()` / `authentication.now()`, so the replay reproduces both.

`GET /__conformance/clock` → `{"now": ms, "wall": ms, "frozen": boolean}`.

`POST /__conformance/clock` with any of:

| Member        | Effect                                                                                                                                                              |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `set: ms`     | Freezes the injected clock at `ms`. It stays there until the next `set` / `advance` / `real`.                                                                       |
| `advance: ms` | Moves the frozen injected clock forward by `ms` (from its current value).                                                                                           |
| `wall: ms`    | Sets the wall clock to `ms`; it then keeps running in real time. Once set, it never runs backwards: a value earlier than the current wall time leaves it unchanged. |
| `real: true`  | Both clocks follow real time again (applied before the other members).                                                                                              |

Without `wall`, `set` and `advance` also move the wall clock to the new injected time. While the injected clock is
not frozen it reads the wall clock. Answer: the same as `GET`.

The runner sends `{ "set": step.at, "wall": step.wall }` before each step (only the members that apply), so every
step runs at the injected and wall times it had while recording (the wall clock a little later when the replay runs
slower than the recording did: it never goes back, because a server refuses records it stamped in the future).

`POST /__conformance/reset` also takes `"initialize": false`: the new instance is built but `initialize()` is not run
(the runner always resets this way before a trace, so migrations run when the trace's `call initialize` step does, or
never, as in the test).

## Outbox (email, SMS, webhooks)

Deliveries of channels configured as `{ "kind": "capture" }` (CONFIG.md, `delivery`) are kept in memory, in delivery
order, as `{"kind": "email" | "sms" | "webhook", ...message}` where `message` is the `DeliveryMessage` the callback
received (`id`, `tenantId`, `to`, `template`, `payload`, `signInUrl`?) or, for webhooks, the `WebhookDelivery` (`id`,
`tenantId`, `webhookId`, `url`, `event`, `body`, `headers`).

- `POST /__conformance/outbox/dispatch` with `{}` or `{"limit": n}` runs the outbox dispatcher once
  (`iam.auth.dispatchOutbox(limit)`) and answers `{"result": {"delivered", "failed", "abandoned"}, "messages": [...]}`
  with exactly the deliveries made during this dispatch, or `{"error": {...}, "messages": [...]}`. A concurrent
  dispatch is refused (409 `CONFLICT`).
- `GET /__conformance/outbox` → `{"messages": [...]}`: every capture since the last reset or clear.
- `POST /__conformance/outbox/clear` → `{"cleared": n}`.

## Events

Audit events handed to `events.onEvent` (channel `delivery.events` with `{ "kind": "capture" }`) are kept in order.

- `GET /__conformance/events` → `{"events": [...]}` (tagged encoding).
- `POST /__conformance/events/clear` → `{"cleared": n}`.

## Script (application callbacks)

The application callbacks a configuration writes as `{"$scripted": true}` (CONFIG.md: `resolveResource`,
`resolveContext`, `authentication.requireMfa`, `authentication.passwordPolicy.isBreached` / `check`,
`domains.resolveTxt`, `regions.locate`, `sts.webIdentity.fetchJson`, `vault.rotators.<name>.rotate`,
`vault.engines.<name>.issue` / `revoke` / `renew`, `auditArchive.write`) answer from a script the runner hands the server before each step:
the answers the recorded callback gave during that step. Each scripted callback is named by its option path.

- `POST /__conformance/script` with `{"answers": [{"id", "callback", "args", "result" | "error", "async"?}], "append"?:
boolean}` replaces the script (or, with `append`, adds to its unused answers; the runner appends for steps that run
  concurrently) and, when replacing, forgets the calls reported so far. Answer: `{"answers": n}`.
- When the server calls a scripted callback it encodes the arguments (tagged encoding) and takes the first unused answer
  for that callback whose `args` are equal (as JSON, member order ignored); failing that, the first whose `args` are
  equal once epoch-millisecond numbers (10^12 to 10^13), ISO-8601 instants and `$argon2…` password hashes are blanked
  out; failing that, the first unused answer for the callback. The answer is consumed. `result` is decoded and returned
  (as a resolved promise when `async` is true, otherwise synchronously); `error` is thrown: `{"iam": true, "code",
"status", "message"}` as an `IamError`, `{"name", "message"}` as a plain error. With no answer left the callback
  throws an error named `ConformanceScriptError` (`No scripted answer for <callback>`).
- `GET /__conformance/script` → `{"calls": [{"callback", "args", "answer"}]}`: every call since the last replacing
  `script` request, in call order, with the arguments the server passed and the `id` of the answer it used (`null`
  when none was left). The runner compares those arguments with the recorded ones, which also binds values the server
  generated for the callback (FORMAT.md, "Replay").

## Reset

`POST /__conformance/reset` with `{}` or `{"config": {...}}` discards the instance and its database (closing it),
clears the outbox, events and script, returns both clocks to real time, and builds a fresh instance on a fresh database from
the same (or the given) configuration, running `initialize()`. Requests that arrive meanwhile wait. Answer:
`{"reset": true}`. The runner uses it to reuse one server process for consecutive traces with the same configuration;
with a file or server database the caller provides an empty database per trace.

## Call

`POST /__conformance/call` with `{"method": "<member path>", "args": [...]}` calls a member of the instance that has
no HTTP route and answers `{"data": <result>}` or `{"error": {...}}` (both tagged). `method` is a dotted path of 1 to 4
identifiers (`__proto__`, `prototype` and `constructor` refused) naming a function on the instance:

- top level: `initialize`, `bootstrap`, `recoverRoot`, `purgeDeleted`, `pruneAudit`, `archiveAudit`, `sweepExpired`,
  `selfCheck`, `sendAccessDigest`, `sendExpiryReminders`, `reconcilePackages`, `closeOverdueCertifications`,
  `closeOverdueTeamReviews`, `checkInvariants`, `detectThreats`, `flushAccessUsage`, `dispatchAuditHooks`,
  `rotateSecrets`, `assertionKey`, `assertionKeys`, `authenticate`, `require`, `callPlugin`;
- the runtimes: `features.*`, `inference.*`, `a2a.*`, `billing.*`, `kms.*`, `pki.*`, `protection.*`, `vault.*`,
  `planResources.*`, `quotas.*`, `privacy.*`, `workflows.*`, `compliance.*`, `applications.*`, `ssh.*`,
  `verifiableCredentials.*`, `ldap.*`, `signals.*`, `licenses.*`, `guests.*`, `clearances.*`, `sessionTokens.*`,
  `hosts.*`, `events.*`, `metrics.*`;
- the authentication service's helpers the tests use: `auth.<method>` (for example `auth.settleBookkeeping`,
  `auth.createIdentity`, `auth.limitAttempt`, `auth.resetRateLimits`, `auth.issueSession`, `auth.requireRecent`);
- API methods that have no route: `api.<group>.<method>` (normally none; the router exposes every group).

Arguments are the in-process arguments, JSON-encoded: credentials stay `{"token": "…"}` or `{"headers": {...}}`
objects. Ports map each name to their equivalent of the TypeScript member; a name they do not have answers 404
`NOT_FOUND` (`Unknown method <path>`).

## Store

Direct access to the instance's database with the `IamStore` contract (the same records, collections and errors as
`@better-iam/core`), for the reads and writes tests make outside the API:

- `POST /__conformance/store` with `{"method": "get" | "find" | "findOrdered" | "insert" | "put" | "delete" |
"collections" | "describe", "args": [...]}` → `{"data": <result>}` or `{"error": {...}}`.
- `POST /__conformance/store` with `{"method": "transaction", "ops": [{"method", "args", "propagate"?}], "rollback"?:
boolean}` runs the operations in order inside one transaction and answers `{"data": {"results": [{"data"} |
{"error"}], "rolledBack": boolean}}`. An operation that fails records its error and the transaction continues,
  unless it has `"propagate": true` (the test let the error escape), which rolls the transaction back.
  `"rollback": true` rolls back after the last operation (a failed recorded transaction, or the runner's dry runs that
  learn the values a transaction reads before it writes them back).
- An operation `{"method": "call", "path": "<member path>", "args": [...]}` inside a transaction calls an instance
  member exactly like `POST /__conformance/call` (same names and resolution), with every `{"$tx": true}` argument
  replaced by the transaction handle: a library call the test made inside its own transaction callback
  (`auth.createIdentity(tx, input)`). Its result or error is recorded like any other operation.
- In the arguments of any operation, `{"$result": [n, ...path]}` stands for what operation `n` (0-based, earlier in
  the same request) returned, or the member at `path` inside it (`[3, "id"]`): the runner refers to records a library
  call created in the same transaction, whose generated IDs it cannot know before the batch runs. A reference to an
  operation that has not run is a malformed request (400 `INVALID_INPUT`).

## Shutdown

`POST /__conformance/shutdown` → `{"shutdown": true}`; the server closes its listener and database and exits 0.
