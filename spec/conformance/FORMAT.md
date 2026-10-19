# Conformance traces: format, binding and normalization

Traces prove behavioral parity. They are recorded from the TypeScript test suite (about 2100 vitest tests), which
exercises the in-process API, and replayed over HTTP against any server started from [CONFIG.md](CONFIG.md) with the
control endpoints of [CONTROL.md](CONTROL.md). The TypeScript server replaying its own traces is the calibration
baseline; Rust and Go must pass the same traces.

```
node scripts/conformance/record.mjs [--out spec/conformance/traces] tests/teams.test.ts tests/vault.test.ts …
node scripts/conformance/replay.mjs [--server "<cmd with {config} and {port}>"] [--traces dir] [--filter text]
                                    [--json report.json] [--jobs n] [--keep-going] [--verbose] [--store url]
node scripts/conformance/serve.mjs --conformance --config better-iam.json --port 4100
```

(`pnpm conformance:record`, `pnpm conformance:replay` and `pnpm conformance:serve` run the same scripts. The
TypeScript server serves the built packages: run `pnpm build` first.) The default `--server` is the TypeScript
server; a port is replayed with, for example, `--server "target/release/better-iam-server --conformance --config
{config} --port {port}"`.

## Recording

Recording is off unless `BETTER_IAM_RECORD=<dir>` is set (`record.mjs` sets it). Then `vitest.config.ts` resolves
`@better-iam/server` to `tests/conformance/recording-server.ts` and `@better-iam/adapter-sqlite` to
`tests/conformance/recording-adapter-sqlite.ts`, and registers `tests/conformance/record-setup.ts`. Nothing else
changes: the wrappers return the very values and promises the library returns and only observe them; the suite passes
the same while recording.

Every `betterIam(options)` call starts one trace. The instance the test gets is a proxy that turns each call the test
makes on the public surface into a step; calls the library makes on itself (and calls made by protocol mounts or
framework integrations while a recorded request runs) are not separate steps. Each test file's traces are written,
when the file finishes, to `<dir>/<test file without .test.ts, "/" → "__">/<NNN>-<test name slug>.jsonl`, replacing
that folder's previous traces.

## File layout

A trace is a JSON Lines file. Line 1 is the header; every further line is one step, in the order the test started
them (`seq` 1, 2, …). The replay runner also reads gzipped traces (`.jsonl.gz`). The checked-in set covers the whole
TypeScript suite; [BASELINE.md](BASELINE.md) reports how the TypeScript server replays it
(`node scripts/conformance/baseline.mjs --report <replay --json report>` regenerates it).

### Header

| Member                  | Meaning                                                                                                                                      |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `type`, `format`        | `"trace"`, `1`.                                                                                                                              |
| `id`                    | `<test file>#<NNN>`: the instance's position among the file's instances.                                                                     |
| `file`, `test`, `tests` | The test file, the test that created the instance (`(file setup)`, `(beforeAll)` for shared ones) and every test that used it.               |
| `replayable`            | False when the configuration cannot be expressed as JSON or nothing can be replayed.                                                         |
| `reasons`               | Why not (or why the replay stops early): `options.plugins is set`, `replay stops before step 12: useProtocol is called with a function`, …   |
| `replayableSteps`       | How many leading steps the replay runs (steps after the first one that cannot be replayed are kept for reference).                           |
| `steps`                 | Number of steps recorded.                                                                                                                    |
| `clock`                 | `{"controlled": true}` when the test injected `authentication.now`.                                                                          |
| `config`                | The `better-iam.json` to start the server with (`configFromOptions`).                                                                        |
| `options`               | The original options in the tagged encoding, functions as `{"$function": name}`, the database as `{"$store": "SqliteStore"}`. Informational. |
| `dropped`               | Observational callbacks left out of `config` (`observability.onSpan`); a trace whose callback threw is cut there.                            |
| `construction`          | `{"error": {...}}` when `betterIam(options)` threw: the server must refuse the configuration the same way.                                   |
| `recordedAt`            | ISO time the instance was created.                                                                                                           |

### Steps

Common members: `type: "step"`, `seq`, `test` (the running test), `kind`, `at` (the injected clock the first time the
step read it), `wall` (the wall clock when it started), `concurrentWith` (the `seq` of steps still running when it
started), `derive` (inputs computed from earlier outputs), `skip` (why the replay stops before this step), `settle`
(true when refused sign-ins' deferred bookkeeping was still being written as the step started: the recorder awaited
`auth.settleBookkeeping()` before running the step, and the replay does the same), `settleAfter` (true when the
step's own refusal left bookkeeping pending: the recorder let it finish before the test saw the answer, as it does over
HTTP before the next request, and the replay settles it after the step), `callbacks` (the calls of scripted
application callbacks during the step, in call order: `{callback, args, result | error, async?}`, tagged encoding;
CONFIG.md rule 3).

| `kind`   | Members                                                                                                                                             | Replayed as                                                                                                                                                                                                                                                      |
| -------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `api`    | `route` (`roles/create`, `auth/signIn`, `authorize`, `authorizeMany`, `listAccessible`), `group`, `method`, `headers`, `input`, `output` or `error` | `POST {basePath}/{route}` with `content-type: application/json`, `x-better-iam: 1`, `host` = the `baseURL` host, the step's `headers`, and `input` as the body. `output` is the `data` of the answer, `error` its `error.code`, HTTP status and `error.message`. |
| `http`   | `request` (`method`, `path` with query, `headers`, `body` or `bodyBase64`), `response` (`status`, `headers`, `body` or `bodyBase64`)                | The same request (the recorded `host` header kept; `content-length`, `connection`, `transfer-encoding`, `keep-alive`, `expect` recomputed). Recorded for `iam.handler(request)` and `iam.nodeHandler(req, res)`.                                                 |
| `outbox` | `method: "dispatch"`, `input` (`{}` or `{limit}`), `messages` (captured deliveries), `output` (the dispatch result) or `error`                      | `POST /__conformance/outbox/dispatch`. Recorded for `iam.auth.dispatchOutbox()`.                                                                                                                                                                                 |
| `call`   | `method` (member path), `args`, `output` or `error` (tagged encoding)                                                                               | `POST /__conformance/call`. Recorded for top-level members and runtimes with no HTTP route (`bootstrap`, `sweepExpired`, `billing.closePeriod`, `auth.settleBookkeeping`, `authenticate`, …).                                                                    |
| `store`  | `method`, `args`, `output` or `error`; for `transaction`: `ops` (`method`, `args`, `output` or `error`, `propagate`, `derive`), `rollback`          | `POST /__conformance/store`. Recorded for the test's own reads and writes of the database (`iam.store`, or the adapter it passed in, also before the instance existed).                                                                                          |

### Credentials

In-process credentials become the HTTP form the router reads:

- `{ token }` → `authorization: Bearer <token>` (the token wins over any headers, as in `auth.authenticate`);
- `{ headers }` → those headers (lower-cased); a `cookie` without an `origin` gets `origin: <baseURL origin>`, which
  the router's CSRF rule requires and in-process calls never check; an `origin` the router would not trust (not the
  `baseURL` origin, not in `trustedOrigins`, and no `hosts` configured) is replaced by the `baseURL` origin when a
  cookie is sent and dropped otherwise, since in-process calls ignore it;
- public routes (`publicApiMethods`, `publicAuthMethods` in `packages/server/src/http.ts`) carry no credential;
  `auth/beginMfa` sends `{tenantId, challenge}` as the body when given a sign-in challenge, otherwise the credential;
  `auth/confirmMfa` sends `{code, rememberDevice?, credential?}` with `credential` only for a challenge.
- calls inside `iam.auth.withClient(client, fn)` carry the client: `user-agent`, and `x-conformance-client-ip` /
  `x-conformance-client-label`, which the trace's `config.http.clientInfo` then reads (`ipHeader`, `labelHeader`);
  when the test's own `clientInfo` has a JSON form, its headers are used instead (a client field it never reads, or a
  value no header can carry, stops the replay there);
- with several `regions` configured the router refuses requests for organizations homed elsewhere (`WRONG_REGION`),
  which in-process calls never meet, so such traces record their API calls as `call` steps (`api.<group>.<method>`,
  `auth.<method>`, `authorize`, …) that the control endpoint makes in process.

`output` is recorded as the HTTP router would answer: `JSON.parse(JSON.stringify(publicResult(result)))` (a top-level
`session` loses `tokenHash` and `uniqueKey`). An error is `{code, status, message, retryAfterMs?}` for an `IamError`
and `{code: "INTERNAL_ERROR", status: 500, message: "Internal server error", thrown}` for anything else.

### Value encoding

`api` and `http` steps are plain JSON (what crosses HTTP). `call`, `store` and outbox values use the tagged encoding
(`scripts/conformance/lib/encode.mjs`): JSON, except `{"$bytes": base64}` (Uint8Array/Buffer), `{"$date": iso}`,
`{"$bigint": "…"}`, `{"$map": [[k, v], …]}`, `{"$set": […]}`, `{"$undefined": true}` (in arrays and arguments),
`{"$number": "NaN" | "Infinity"}`, `{"$headers": {…}}`, `{"$error": {name, message, code?, status?}}`,
`{"$function": name}`, `{"$promise": true}`, `{"$cycle": true}`, and `{"$object": ClassName}` for an instance without
own enumerable members. Object members that are `undefined` are left out, as in JSON.

### Derived inputs (`derive`)

Some inputs are computed by the test from an earlier output, so the recorded value cannot be bound. The recorder
recognizes two kinds and the replay recomputes them from the bound values:

- `{"kind": "totp", "secret": <recorded base32 secret>, "window": n, "target", "path"}`: a 6-digit code equal to
  TOTP(secret) (RFC 6238, SHA-1, 30 s, 6 digits) for a secret that appeared earlier in an output (a member named
  `*secret*`, or an `otpauth://` URI). The replay sends TOTP(bound secret, T + n·30 s) where T is the injected clock
  at the step (the wall clock for traces without a controlled clock).
- `{"kind": "sha256", "of": <recorded value>, "target", "path"}`: a lowercase hex SHA-256 of a string the server
  returned earlier (a token whose stored hash the test looks up). The replay sends sha256(bound value).

`target` names what `path` points into: `input` (api), `args` (call and store; per operation inside `ops`), `body`
(the JSON body of an http step).

### Replayability

A trace is not replayable when its options use something `better-iam.json` cannot express (CONFIG.md, rule 4), its
database is shared with another instance, is a wrapped or custom store, or is a file opened by several handles. The
replay stops before the first step that:

- passes or returns a function (`events.subscribe(fn)`, `useProtocol(…)`, `inference.gateway()`), or is called inside
  a store transaction callback (except an instance member called with the transaction itself, which becomes a `call`
  operation of the transaction), or inside `withClient` for a `call`;
- was never awaited by the test;
- follows a test callback (delivery, `onEvent`, a scripted callback) that threw (delivery), wrote to the store or
  called the library, or another instance opening the same database, or a scripted callback called outside any step;
- made the server send a request to a loopback or private address (a JWKS, discovery, poll or webhook endpoint the test
  runs, which the replay cannot reach; names that do not resolve fail the same way in every run and stay replayable);
- carries a WebAuthn response (`clientDataJSON` of type `webauthn.create` / `webauthn.get`), which the test's
  authenticator signed over a challenge that differs in every run;
- sent, through the fetch `handler`, a body larger than the Node transport accepts (64 KiB under `basePath`, 2 MiB
  elsewhere): the standalone server answers those with `nodeHandler`'s plain 413;
- pages through records with a keyset cursor (`{ after: <generated ID> }`): page membership follows random IDs;
- got an answer from a scripted callback that repeats a value the server generated for that very call (the replay
  prepares answers before the call, so it would hand back the recorded value), or called a scripted callback the test
  held open while later steps finished;
- has an API input over the router's 64 KiB body limit (in-process calls have none), went through a web framework
  before `nodeHandler` (Express, Fastify and Nest set headers or read the body first), or sent a header value no
  HTTP/1.1 request can carry;
- appends to the audit hash chain itself (`appendAuditEvent(tx, …)` from the test), runs after the test replaced the
  database's methods with its own hooks, bounds a time range (`from`, `until`, …) by instants it read from its own
  clock, or reads `metrics.*` counters (they depend on the transport the calls used).

## Replay

For each replayable trace the runner starts the server command with the trace's `config` (or resets an idle server
that has the same configuration), resets it with `"initialize": false` (the trace's own `call initialize` step runs
the migrations, as the test did), then replays `replayableSteps` steps. A trace recorded on a database file has
`"store": {"kind": "sqlite", "path": "file", …}` (with the test's journal and durability settings): the runner gives it
a new, empty file of its own. Before a step it sets the clocks to the
step's `at` (when the clock is controlled) and `wall`. A step waits for every earlier step except those listed in its
`concurrentWith`, so steps the test ran concurrently run concurrently. The runner stops a trace at its first failing
step (`--keep-going` continues), then prints `PASS`/`FAIL` per trace with the first differences, a per-API-group
table of replayed steps, and the reasons traces or their tails were not replayed. `--json` writes everything.

A transaction that reads a record and writes it back is first run and rolled back (`rollback: true`) until the values
it writes stop changing, so values first seen by its own reads are bound before the real run. A transaction operation
`{"method": "call", "path", "args"}` (arguments with `{"$tx": true}` for the transaction) is an instance member the
test called inside its transaction callback with the transaction (`auth.createIdentity(tx, input)`).

Within a transaction, an argument equal to (a member of) what an earlier `call` operation returned is sent as
`{"$result": [n, ...path]}` (CONTROL.md, "Store"), since the IDs a batched transaction generates cannot be bound
before it runs.

Before a step with `settle`, and after a step with `settleAfter`, the runner calls `auth.settleBookkeeping` (control
`call`). When the recording shows the test waiting in real time between two steps (the wall clock moved further than
the replay has taken), the runner waits as long (up to 10 s) before the next step, since the server's timers (usage
flushes, for example) run on real time. In a trace whose configuration
has scripted callbacks, the runner sends the step's `callbacks` (bindings substituted, each with an `id`) as the script
before the step, and afterwards compares the calls the server reports (`GET /__conformance/script`) with the recorded
ones as an unordered list of `{callback, args}` (steps that ran concurrently with others are not compared), binding
what the server generated and passed to a callback.

### Binding

Generated values differ on every run. The runner keeps a binding table from recorded to actual values, filled by
position while comparing outputs, and substitutes it into every later input (bodies, headers, paths, arguments,
object keys):

- **Strings.** Each string is split into a stable skeleton and its generated tokens: PEM blocks, PHC password hashes,
  JWS/JWT (and SD-JWT `~` disclosures), UUIDs, `biam_<type>_` credential tokens, prefixed identifiers
  (`usr_` + 22 base64url), standard base64 with `+`/`/` (20+ characters), and base64url/hex/base32 runs of 16+
  characters that look random (letters and digits, base32 alphabet, or mixed case with short camel segments). When
  the skeletons match, each differing token pair is bound. Members whose name ends in `id`, `token`, `secret`,
  `challenge`, `code`, `nonce`, `hash`, `salt`, `signature`, `jti`, `kid`, `serial`, `fingerprint`, `sealed`,
  `password`, `otp` or `lease` also bind short code-like values (4-10 digits, or 8+ characters with a digit);
  `number`/`reference` members bind reference codes with the same layout (`DSR-AXGF0YR8`).
- **Consistency.** A bound recorded value must come back as its binding everywhere later, and one actual value cannot
  stand for two recorded ones. A generated-looking token that comes back unchanged (one the test made up, a
  deterministic hash) is bound to itself, so it cannot later be paired with another value.
- **Secrets by member.** Under members ending in `value`, `password` or `secret`, generated passwords (16+ characters
  of the same length, no whitespace or URL syntax, three or more character classes and at least two punctuation
  characters outside base64url) are bound like tokens; under the volatile members above, base64url runs of 16+
  characters bind without needing a digit (`sealed` values).
- **Instants.** Wall-clock instants that agreed (below) are bound too: epoch milliseconds as numbers and inside
  strings, so a test that passes one back (`until: event.timestamp`) sends the server's own.
- **Records.** An object with a generated `id` seen in an output is remembered with its actual counterpart; when an
  input carries an object with that `id`, every member the test left unchanged takes the actual record's value
  (tests that read a record and write it back, possibly modified).
- Inputs are substituted whole first (a bound string), then by every bound run of 12+ characters inside them.

### Normalization

- **Arrays** are compared in order; if that fails, each recorded element takes the unused actual element that agrees
  with the fewest new bindings (its own position first; for lists over 200 elements the first that agrees), because
  lists sorted by generated IDs come back in another order, and the right partner shares the values both runs agree on. Arrays of audit
  events (objects with numeric `sequence` and string `hash`) whose sequence numbers form the same set also match when
  only `sequence`, `hash` and `previousHash` differ: one operation appended the same events in an order that follows
  generated IDs.
- **Objects** must have the same members; members keyed by generated values are paired by value.
- **Numbers** must be equal, except instants (epoch milliseconds, and epoch seconds in `exp`/`iat`/`nbf`/`auth_time`/
  `validAfter`/`validBefore`): with a controlled clock an instant a whole number of seconds from the step's injected
  clock value must be exact (it came from the injected clock); any other instant, and every instant without a
  controlled clock, may differ by up to 30 s (wall-clock readings), or by the time between recording and replay for
  traces recorded without `wall`. `latencyMs`, `durationMs`, `elapsedMs`, `tookMs`, `sumSeconds` are not compared.
  ISO-8601 instants (`2026-10-19T09:06:41.583Z`), alone or inside strings, follow the same rule.
- **Errors**: code, HTTP status and message (messages after substitution). For `INTERNAL_ERROR` only code and status.
- **Documents**: two multi-line strings whose lines differ only in order (rows of an invoice page or a CSV export
  that follow generated IDs) agree, their lines compared as a list.
- **Pairing cost**: an instant that agrees only within the time tolerance counts like a new binding when list
  elements are paired, so an exact partner wins.
- **HTTP responses**: status, every recorded header except `date`, `connection`, `keep-alive`, `transfer-encoding`,
  `content-length`, no unexpected headers, `set-cookie` values as an unordered list (a cookie's `Max-Age` and
  `Expires` agree within the time tolerance), JSON bodies as JSON, Prometheus
  text (`text/plain; version=0.0.4`) by its `# HELP`/`# TYPE` lines only (counts depend on how calls arrived).
- **Outbox**: captured messages as an unordered list, then the dispatch result.

### Tolerances

[`tolerances.json`](tolerances.json) lists the places where the reference implementation itself is not
reproducible (orderings by random IDs in titles, rollout buckets hashed from random tenant IDs, races a test provokes
on purpose). Each entry has `trace`, `test` and `step` globs (default `*`), JSON `paths` (globs, `[*]` for any index)
that are then not compared at all, and a `reason`; `"concurrent": true` limits an entry to steps that ran alongside
another step (one side of a race). Steps where an entry applied report `tolerated`. Adding an entry
needs a reason why no implementation can reproduce the recorded value; a port-specific difference never goes there.
