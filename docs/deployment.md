# Deployment and release

## Runtime and configuration

Use Node.js 22.12 or a newer supported LTS release. The CI matrix covers Node 22/24 on Windows/Linux. SQLite uses a native driver; libSQL uses `@libsql/client` (local files, embedded replicas, and remote Turso or sqld databases); PostgreSQL uses `pg`. Edge runtimes are not supported by the complete authentication/protocol server.

Provide a stable high-entropy `BETTER_IAM_SECRET`, HTTPS base URL, trusted browser origins, persistent database, and delivery callbacks. OAuth signing JWKs, OAuth encryption key, OAuth cookie keys, and SAML signing/decryption keys are separate explicit inputs. No production signing keys are generated in request handlers.

`@better-iam/server` depends on `jose` (^6.1.3) for session JWTs, provider token verification, and the runtime-neutral `@better-iam/server/session-tokens` verifier, the only server entry point that runs on edge runtimes.

## CLI

```sh
better-iam init --database sqlite --config better-iam.config.mjs
better-iam migrate --config better-iam.config.mjs
better-iam bootstrap --config better-iam.config.mjs
better-iam doctor --config better-iam.config.mjs
better-iam outbox --config better-iam.config.mjs
better-iam purge --config better-iam.config.mjs
better-iam audit-verify --config better-iam.config.mjs --tenant TENANT_ID
better-iam audit-export --config better-iam.config.mjs --tenant TENANT_ID --output audit.jsonl
better-iam audit-prune --config better-iam.config.mjs --tenant TENANT_ID --retention-days 365
better-iam analyze --config better-iam.config.mjs --tenant TENANT_ID --fail-on high
better-iam config-export --config better-iam.config.mjs --tenant TENANT_ID --output tenant.json
better-iam config-plan --config better-iam.config.mjs --tenant TENANT_ID --input tenant.json --prune
better-iam config-apply --config better-iam.config.mjs --tenant TENANT_ID --input tenant.json --prune
better-iam report --config better-iam.config.mjs --tenant TENANT_ID --within-days 30 --unused-days 30
better-iam digest --config better-iam.config.mjs --within-days 30 --unused-days 30
better-iam remind --config better-iam.config.mjs --within-days 7
better-iam reconcile --config better-iam.config.mjs
better-iam close-certifications --config better-iam.config.mjs
better-iam mine-roles --config better-iam.config.mjs --tenant TENANT_ID --peer-by attribute:department
better-iam check-invariants --config better-iam.config.mjs --tenant TENANT_ID --fail-on-broken
better-iam monitor-invariants --config better-iam.config.mjs
better-iam detect-threats --config better-iam.config.mjs --max-events 2000
better-iam store-export --config better-iam.config.mjs --output snapshot.jsonl
better-iam store-import --config better-iam.config.mjs --input snapshot.jsonl
better-iam store-copy --config better-iam.config.mjs --target-config target.config.mjs
better-iam sweep --config better-iam.config.mjs --retention-days 30
better-iam rotate-secrets --config better-iam.config.mjs --dry-run
better-iam audit-archive --config better-iam.config.mjs
better-iam audit-verify-archive --directory /var/lib/better-iam/audit --tenant TENANT_ID
```

`--config` is optional: the CLI finds the nearest `better-iam.config.*`, reads `BETTER_IAM_CONFIG`, or runs from `BETTER_IAM_DATABASE_URL` and `BETTER_IAM_SECRET` alone. The [CLI guide](cli.md) covers that, `login` and saved sessions, `api` for any API method, configuration as code in TypeScript, output flags, exit codes, and project commands; `better-iam help <command>` prints each command's flags and environment variables.

Before bootstrap, supply `BETTER_IAM_ROOT_EMAIL`, `BETTER_IAM_ROOT_NAME`, and `BETTER_IAM_ROOT_PASSWORD` through environment variables. Passwords are not accepted on command lines. The bootstrap result contains tenant/identity IDs and indicates that MFA enrollment is required. `recover-root` uses the same environment variables to create a deployment-recovery administrator, recording the action.

`purge` removes tombstoned tenants past their retention window (default 30 days; `--retention-days` accepts 0–3650) and reports the purged tenants and number of deleted records. It is idempotent and preserves audit records.

`audit-verify` recomputes one tenant's audit hash chain straight from storage and exits non-zero when it does not verify; `audit-export` writes the chain as JSON Lines to a new file (it refuses to overwrite). Both are deployment operations: they need no credential and record no audit event. `audit-prune` deletes events older than `--retention-days` (default 365) after you archived them and appends an `audit:prune` checkpoint so the remaining chain still verifies. With `auditArchive` configured it enforces that order: it never deletes an event the archive does not hold yet (see [continuous audit archiving](#continuous-audit-archiving)). `doctor` reports the number of chained tenants and events, and under `storage` the adapter's own view (`IamStore.describe()`): schema version, applied migrations with their times, record counts per collection, and settings such as SQLite's journal mode, synchronous level, and file size, or PostgreSQL's server version and `synchronous_commit`.

`doctor` also prints `findings` from `iam.selfCheck()`, each with a severity, a message, and a fix. `ok` is false when any finding is an error. The checks cover:

- **Errors:** a schema behind this release, no root tenant, and a SQLite rollback journal at `durability: 'normal'`.
- **Storage warnings:** an in-memory database and PostgreSQL with `synchronous_commit = off`.
- **Configuration warnings:** a placeholder-like secret, a short metrics token, and no `sendEmail` transport.
- **Jobs that are not running:**
  - records due for the retention sweep for more than two days, judged with the sweep's own retention;
  - expired bindings or challenges older than a day (`purge`);
  - outbox messages waiting more than 15 minutes, and messages abandoned in the last day;
  - audit hooks waiting more than 15 minutes (dispatch them in the process that registers subscribers).

`doctor` exits 0 whenever it can connect, including to a database without the IAM schema. Add `--strict` to exit non-zero (`DOCTOR_FINDINGS`) on any error or warning, for example as a deployment gate. Pass the `--retention-days` your sweep uses (default 30), or `deliveryRetentionMs` and `graceMs` to `selfCheck`, so the backlog is judged the same way. The checks only read, and `selfCheck({ cap })` bounds how many records each backlog check counts.

`store-export`, `store-import`, and `store-copy` move a whole deployment between databases and adapters, for example from SQLite to PostgreSQL. `store-export` writes every record as a JSON Lines snapshot to a new file (a header, one line per record, and a trailer with counts). It reads in one transaction, so the snapshot is consistent, but that also holds the write lock until it finishes. `store-import` migrates the schema of the configured database, which must hold no records yet, and loads a snapshot in one transaction. A truncated or corrupt snapshot, a count that disagrees with the trailer, or a record the database refuses rolls everything back. `store-copy` does both in one step, from the configured database into the empty database of `--target-config`. Records are copied verbatim, so password hashes, sessions, encrypted secrets, and audit chains stay valid as long as the target configuration uses the same `secret`. Run `migrate` with the target configuration afterwards, and on PostgreSQL follow a bulk import with `VACUUM ANALYZE iam_records`. A snapshot holds credential hashes and encrypted secrets, so protect it like the database itself. The same operations are available as `exportStore`, `importStore`, and `copyStore` in `better-iam/core`.

`analyze` prints a tenant's access-analysis findings as JSON (see [policies](policies.md#access-reviews)). It acts as the session or API key in `BETTER_IAM_TOKEN`, which needs `iam:analysis:read`, so each run is authorized and audited. `--dormant-days N` changes when unused accounts are reported, and `--fail-on high|medium|low` exits non-zero when an unsuppressed finding of that severity or higher exists, which suits a nightly job or a deployment gate.

`config-export`, `config-plan`, and `config-apply` are configuration as code (see [policies](policies.md#configuration-as-code)): the export writes a tenant's roles, policies, groups, tenant-defined resource types, and group bindings as JSON (to a new file with `--output`, otherwise to standard output), the plan prints the creates, updates, and deletes a file implies without writing anything, and the apply performs them in one transaction; `--prune` also deletes items of a listed kind that the file omits, and `config-plan --fail-on-drift` exits non-zero (`CONFIG_DRIFT`) after printing the plan when anything would change, which turns it into a CI check. All three act as the session or API key in `BETTER_IAM_TOKEN` (`iam:config:read`, and `iam:config:apply` plus the permission for each change), so they are authorized and audited exactly like the console.

`report` prints a tenant's access report (`reports.access`) as JSON: identities and temporary bindings ending within `--within-days` (30), API keys unused for `--unused-days` (30) or ending soon, live just-in-time activations, and the number of activation requests awaiting approval. It acts as `BETTER_IAM_TOKEN` (`iam:identities:read`, plus `iam:bindings:read` and `iam:credentials:read` for the binding and key sections, which are otherwise omitted), which makes it a good nightly job to pipe into a ticket or chat channel.

`digest` (`iam.sendAccessDigest`) is the same report delivered by email: for every active organization (or one `--tenant`) whose report has findings, the owners receive an `access-digest` message carrying the counts and the full report as JSON, at most once per 20 hours per organization, and the run is recorded as `tenant:access-digest`. It is a deployment operation like `purge`, needs the configured `sendEmail` callback, and belongs in the same scheduler; run `outbox` afterwards to deliver the messages.

`remind` (`iam.sendExpiryReminders`) speaks to the people themselves: everyone whose account, direct role bindings, group memberships, or package assignments end within `--within-days` (seven) gets one `expiry-reminder` email listing them (`items` as JSON with kind, name, and end), once per item and end date, so extending the access brings a fresh reminder when the new end comes into the window. Each reminder is recorded as `identity:expiry-reminder` on the person. Same requirements as `digest`; schedule it daily beside it.

`reconcile` (`iam.reconcilePackages`) applies access-package rules (see [policies](policies.md#automatic-assignment-birthright)): it assigns and removes automatic assignments under each rule owner's authority, at most `--limit` (1000) changes per organization per run (`truncated: true` means run again), with `--tenant` and `--package` to scope it and `--package ID --confirm` to release changes the brake held back. It prints the result as JSON (`assigned`, `refreshed`, `restored`, `ending`, `revoked`, `stale`, `failed`, `suspended`, `braked`). Schedule it every 15 minutes after `purge`, because SCIM provisioning, invitations, and group changes only take effect through it; `--fail-on-attention` turns failures, suspensions, and held-back changes into a non-zero exit for alerting. A deployment operation like `remind`: no credential, no email transport.

`close-certifications` (`iam.closeOverdueCertifications`) applies every access-certification campaign created with `autoClose` whose due date has passed (or only one `--tenant`'s), each in its own transaction, under the campaign creator's grant authority, and prints `{ closed, skipped }`; each run is recorded as `certification:auto-close`. It needs no credential and no email transport; schedule it with the others.

`detect-threats` (`iam.detectThreats`) runs [threat detection](threat-detection.md): for every active organization (or one `--tenant`) it reads up to `--max-events` (2000, at most 20,000) unread audit events from the organization's cursor, verifies their hash chain, raises detections and incidents, updates identity risk, and runs the response playbooks. It prints `{ tenants, eventsScanned, detections, incidentsOpened, responses, braked, chainBreaks, pending }`; `pending` counts organizations with more to read, which the next run continues. Schedule it every minute, followed by `outbox` for the alert emails; it needs no credential and is safe to overlap.

The CLI loads the default export of a trusted `.mjs` configuration file, either options or a factory. Initialization refuses to overwrite an existing configuration.

## Persistence and operations

Run migrations deliberately at deployment; `initialize()` is idempotent for built-in schema migrations. Maintain backups. The initial schema is a generic collection store, and service-level transactional validation supplies relationships; do not edit records directly.

All adapters serialize IAM transactions. Avoid network requests inside application transactions. There is no distributed policy cache to invalidate.

Record lookups run in SQL. Scalar filter fields become typed JSON conditions, and results are paged in SQL whenever the whole filter could be expressed there. Hot lookup fields are indexed, including session token hashes, identity and group ids, email addresses, and OAuth artifact hashes (`INDEXED_FIELDS` in `better-iam/core`). SQLite and libSQL use one partial expression index per field. PostgreSQL uses a single `jsonb_path_ops` GIN index over the document plus B-tree indexes on tenant and natural key. Each schema step is recorded by name in the `iam_migrations` table.

- **PostgreSQL:** rows written after the GIN index exists wait in its pending list until a vacuum merges them. Autovacuum does this in normal operation. After a bulk import, run `VACUUM ANALYZE iam_records` so lookups use the index immediately.
- **PostgreSQL value encoding:** `jsonb` cannot hold U+0000 or unpaired surrogates, so the PostgreSQL adapter stores such strings, and object keys, in a reversible encoding (`encodeJsonbDocument` in `better-iam/core`) and decodes them on every read. Applications see the original values. Filters on such values are evaluated in memory.
- **Upgrading an existing database:** migration `0002_query_indexes` builds its indexes inside the migration transaction. That blocks IAM writes, but not reads, for the duration on large tables, so run it in a maintenance window. On PostgreSQL it first rewrites existing rows that need the value encoding. A migration waits up to ten minutes for another instance's migration. Instances of the previous release keep working during a rolling upgrade, but on PostgreSQL they would read encoded values raw, which only matters for records holding U+0000 or unpaired surrogates.
- **libSQL:** `@libsql/client` compiles each statement on every call, and SQLite compile time grows with the number of indexes an insert maintains. Local libSQL writes therefore cost more than the SQLite adapter's, which caches prepared statements.
- **SQLite durability:** file databases run in write-ahead-log mode with `synchronous = FULL` by default, so readers in other processes never block the writer and a committed transaction survives power loss. `sqliteAdapter({ journalMode: 'delete' })` restores the rollback journal, for example on network file systems that cannot share WAL memory. `durability: 'normal'` trades the last transactions before a power failure for faster commits. In WAL mode that never corrupts the database; with `journalMode: 'delete'`, keep `durability: 'full'`, because a power failure at NORMAL can corrupt a rollback-journal database.
- **Ordered reads:** audit listings, exports, and retention pruning page through events in timestamp or sequence order in SQL (`IamStore.findOrdered`, migration `0003_ordered_indexes`), so their cost follows the page size rather than the length of the log. Migration `0005_lookup_indexes` indexes `sourceSessionId` and `trustId` on SQLite and libSQL for session cascades (PostgreSQL's document index already covers them). Migration `0004_expiry_indexes` adds collection-wide indexes on `expiresAt`, `deliveredAt`, and `failedAt` for the retention sweep; like `0002`, it builds them inside the migration transaction, so run it in a maintenance window on a large database.
- **Retention sweep:** sign-ins, OAuth and SAML flows, and deliveries leave records behind after they stop mattering. Without a sweep, storage and some scans grow with traffic; `dispatchOutbox`, for example, reads the whole outbox. Schedule `iam.sweepExpired()` (CLI `sweep`) beside `purge`, every hour or daily. It walks the expiry indexes oldest first in batches of 500 per transaction and deletes at most `limit` (10,000) records per run. When it stops at that limit it reports `truncated: true`; more records may be due, so run it again. It deletes:
  - user and role sessions, session tokens, trusted devices, and relationship tuples past their expiry;
  - redeemed web-identity token records (`webIdentityReplays`) once the token they record could no longer be presented (its expiry plus the largest clock tolerance a provider may be given, 120 seconds, so raising a provider's tolerance later cannot reopen a redeemed token);
  - OAuth artifacts and login states, and SAML request, relay-state, and assertion-replay records past their expiry. OAuth grants stay 31 days past their expiry, so back-channel logout still reaches the client when a bound session ends later;
  - delivered or abandoned outbox messages, and abandoned Shared Signals deliveries, once they are older than `deliveryRetentionMs` (CLI `--retention-days`, default 30 days). Age is counted from delivery or abandonment. This also bounds the webhook delivery history and `redeliver`;
  - audit hook rows already dispatched.

  A `graceMs` margin (five minutes) past expiry absorbs clock skew between instances. Some records are never deleted by age:
  - pending deliveries;
  - API keys and any session kind other than user, role, and session token (API keys are listed as expired and can be renewed);
  - invitations, access requests, usage records, and SCIM connections.

  Expired challenges, rate-limit windows, blocks, bindings, and memberships are removed by `purge`.

- **Session activity:** validating a session updates its `lastSeenAt` at most once a minute, or once per tenth of the idle timeout when that is shorter. Busy clients therefore do not turn every request into a write, and idle expiry stays accurate to that interval.
- **Measuring:** `instrumentStore(store, onCall)` from `better-iam/core` reports every read, write, `collections`, and `describe` call, with its collection, filter keys (never values), record count, and duration. Use it for slow-query logs and capacity planning. `pnpm bench:scale` seeds a deployment of `BENCH_IDENTITIES` identities (default 5000). It prints per-operation latency and storage calls over `BENCH_ITERATIONS` runs of each operation (default 40).

Run `iam.auth.dispatchOutbox()` and `iam.events.dispatch()` (also available as `iam.dispatchAuditHooks()`) from your application's worker schedule. The outbox carries email, SMS, and webhook deliveries in creation order; a failed attempt is retried with exponential backoff from thirty seconds to one hour and abandoned after `authentication.maxDeliveryAttempts` (default 25) with `failedAt` and `lastError` recorded. `dispatchOutbox` returns `{ delivered, failed, abandoned }`. Schedule `iam.purgeDeleted({ retentionMs })` from the same worker: it removes tombstoned tenants past their retention window, including plugin-owned records through plugin purge callbacks, deletes expired temporary bindings and ended role activations, marks stale access requests expired, and disables identities past their scheduled deactivation (`expiresAt`), revoking their sessions and recording `identity:expire`; it also removes lapsed temporary group memberships (with the activations they carried) and reports `purgedTenants`, `deletedRecords`, `expiredBindings`, `expiredRequests`, `expiredIdentities`, `expiredActivations`, and `expiredMemberships`; each purged root records one audit event. Expired identities and activations are refused at their next use even before the worker runs, so the schedule only affects how quickly status and reports catch up. Delivery is at least once; use message IDs for deduplication and alert on persistent failures. Delivery callbacks are invoked outside the write transaction. Audit records omit passwords, keys, and token bodies.

Authentication rate limits are configurable through `authentication.rateLimits`: `attempts` (default 10) for ordinary flows such as password sign-in, `sensitiveAttempts` (default 5) for MFA, recovery, and delivery requests, `windowMs` (default fifteen minutes), and a pluggable `limiter`. The default limiter keeps durable counters in the IAM database; multi-instance deployments that prefer a shared cache can supply one that implements `consume()`. `createMemoryRateLimiter()` serves single-process deployments and tests. Refusals (`RATE_LIMITED`, 429) carry `retryAfterMs` in the error body and a `Retry-After` header equal to the window, so clients and proxies can back off. `ipAttempts` (off by default) adds a counter per client IP and tenant that every authentication flow shares, so credential stuffing and password spraying from one address stop after that many attempts per window no matter how many accounts it names; it only works with a recorded IP (`http.clientInfo` behind your proxy), and `identities.unlock` clears a person's counters but never the network's, so size it for the largest office behind one NAT. `authentication.failedSignInAlerts` (off by default; needs `sendEmail`) emails a person once their failed attempts since their last sign-in reach that number (`sign-in-failures` template: `attempts`, `time`, `ip`, `userAgent`), once per streak.

Observe authentication failures, rate-limit responses, denied/root-override audit events, database busy errors, outbox retries, token issuance, and revocation. Public errors do not expose SQL or raw protocol assertions.

`authentication.trustedDeviceLifetimeMs` caps "remember this device" for the whole deployment (default 30 days, at most one year; 0 disables it). A browser that completed MFA with `rememberDevice` receives a device token; through the HTTP handler it lives in the `better-iam.device` cookie and is injected into later `auth/signIn` and `auth/finishPasswordless` requests, so the client only has to send `rememberDevice: true` once. `auth/revokeTrustedDevices` clears the cookie. Tenants shorten or disable the window with `trustedDeviceDays`. `authentication.signInNotifications` queues a `new-sign-in` email (payload: `sessionId`, `time`, `method`, `userAgent`, `ip`, `label`) whenever a session starts from a client that none of the person's live sessions or remembered devices has used; tenants override the default with `notifyNewSignIn`. Only sessions with client details qualify, so run sign-ins through the HTTP handler or `auth.withClient`. The same recorded IP drives a tenant's `allowedIpRanges` (sign-in and session network allowlist), which is therefore only meaningful with `http.clientInfo` in place.

Sessions issued through the HTTP handler record the client's `User-Agent` as `session.client.userAgent`. Behind a proxy you control, supply `http.clientInfo(request)` to record the real IP (from the header your proxy sets), the user agent, and an optional device `label`; values are trimmed and bounded, and nothing about the client is ever used for authorization. `auth.listSessions` returns the details for device lists and `auth.revokeOtherSessions` ends every other session of the caller (recent authentication required). Sessions created directly through `iam.api.auth.*` record client details only inside `iam.auth.withClient(info, fn)`. The same `http` block takes `cookieSameSite` (`lax`, the default, or `strict`) and `persistentCookies` (`true` by default; `false` issues browser-session cookies unless a sign-in request sends `X-Better-IAM-Persistent: 1`).

Every JSON response from the handler carries `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`. A plain `X-Request-Id` header (letters, digits, `._:-`, at most 128 characters) is echoed on the response, success or error, and appears as `requestId` on the request's `http` span, so IAM latency and outcomes join your gateway's request logs.

`observability.onSpan` receives one span per unit of work after it completes: `operation` (named by action), `authorize` and `listAccessible` (named by action), `authorizeMany`, `auth` (named by the authentication method, such as `signIn`), and `http` (named by the request path, with `status`). Each span carries `tenantId` when known, `outcome` (`ok`, `denied` for 401/403/429 refusals and advisory denials, or `error`), the `code`, and `durationMs`. The handler must be synchronous and cheap; exceptions it throws are ignored. Feed spans to a metrics library or tracer:

```ts
observability: {
  onSpan(span) {
    latency.observe({ kind: span.kind, name: span.name, outcome: span.outcome }, span.durationMs);
  },
},
```

`observability.metrics` keeps Prometheus-style counters and histograms from those spans without any extra dependency: `better_iam_spans_total{kind,name,outcome,code}`, `better_iam_span_duration_seconds{kind}` (configurable `buckets`), and `better_iam_http_requests_total{path,status}`. Names the caller controls (unknown routes, rejected input) collapse into `(invalid)` / `(unknown)`, and series beyond `maxSeries` (2000) collapse into `(other)`, so a hostile client cannot grow memory. Render them yourself with `iam.metrics.render()` (or inspect `snapshot()`), or set `bearerToken` and point a scraper at `GET {basePath}/metrics` with `Authorization: Bearer <token>`. With `gauges: true` each scrape also reports `better_iam_outbox_messages{state="pending"|"failed"}` and `better_iam_sessions_live{kind}` read from storage at that moment. `GET {basePath}/health` is always available: one database read, `{ status: 'ok' | 'unavailable', database, latencyMs }`, status 503 when the store fails, and nothing else about the deployment.

```ts
observability: { metrics: { bearerToken: process.env.METRICS_TOKEN } },
```

Export each tenant's audit chain to independent storage on a schedule (`iam.api.audit.export`, paging with `nextSequence`) and verify it (`iam.api.audit.verify`, or `verifyAuditChain` against the archive). The first `initialize()` after upgrading to a chained version backfills existing audit events in one transaction; on very large logs, run it during a maintenance window. See [events](events.md).

### Continuous audit archiving

Configure `auditArchive` and schedule `iam.archiveAudit()` (CLI `audit-archive`) every few minutes to keep an independent copy of every tenant's audit chain:

```ts
import { createJsonlAuditArchive } from 'better-iam/server';

auditArchive: createJsonlAuditArchive({ directory: '/var/lib/better-iam/audit' }),
// or your own sink, write-once per range:
// { write: (batch) => putObjectIfAbsent(`${batch.tenantId}/${batch.fromSequence}-${batch.toSequence}`, batch) }
```

Each run reads every tenant's events after its archive cursor (collection `auditArchiveCursors`), in chain order and in batches (`batchSize`, 1,000 by default). Each batch is checked with `verifyAuditChain` against the previous batch's `lastHash` before it is handed to `write`. The cursor moves only after `write` resolves, so a batch can be written again after a crash, possibly covering a longer range. A sink must therefore meet two conditions:

- key stored batches by `tenantId`, `fromSequence`, and `toSequence`;
- never replace a stored batch with different content, and throw instead.

One run at a time holds a tenant: a lease on its cursor (`leaseMs`, 10 minutes by default) that the run renews before each batch. A second run skips the tenant and lists it under `busy`, so overlapping schedules or instances never race each other's batches.

- A chain that does not verify (for example an edited row) is reported under `failed` with `AUDIT_CHAIN_BROKEN`, and nothing past it is archived.
- A failing sink is reported with `ARCHIVE_WRITE_FAILED`, and a batch that conflicts with a stored one with `ARCHIVE_CONFLICT`. The CLI exits non-zero in all three cases.
- Sequences deleted before they were archived are listed under `gaps`.

`createJsonlAuditArchive` writes one file per batch, `{tenantId}/{fromSequence}-{toSequence}.jsonl` with zero-padded sequences. Files are write-once: each is written under a unique temporary name, flushed, and published with a hard link that never replaces an existing file, and the directory is flushed too (not possible on Windows). Writing the same batch again is accepted; different events under an existing name are refused with `ARCHIVE_CONFLICT`. A restored or tampered database therefore cannot overwrite archived events. After a crash, files can overlap; read them by `sequence`. `better-iam audit-verify-archive --directory DIR --tenant ID` checks one tenant's archive on its own, without the database. It verifies that overlapping copies agree, that no sequence is missing, and that every hash and link recomputes, and exits non-zero (`AUDIT_ARCHIVE_INVALID`) otherwise.

Once a tenant has an archive cursor, or wherever `auditArchive` is set, `pruneAudit` (CLI `audit-prune`) deletes only events the archive already holds. This holds in every process, including ones without the option. It reports `heldForArchive: true` when it stopped early, so the database never drops an event the archive lacks. `doctor` reports `audit-archive-behind` when a tenant has unarchived events older than a day.

## Rotating the deployment secret

The deployment `secret` encrypts authenticator (TOTP) secrets, webhook signing secrets, and undelivered email, SMS, and webhook payloads, including queued invitation emails. It also keys the digests of one-time challenges: password reset, email verification and change, passwordless links and codes, MFA sign-in, phone verification, and passkey ceremonies. It derives the assertion signing key too.

Some credentials do not depend on the secret, so a rotation leaves them alone:

- sessions and API keys, which are hashed without it, so nobody is signed out;
- invitation links, whose tokens are plain SHA-256 hashes;
- OAuth, SAML, SCIM, and Shared Signals, which use their own keys;
- signed session tokens (JWTs), which use their own `sts.jwt.signingKeys` and `verificationKeys`.

Replacing the secret outright makes every enrolled authenticator and webhook unusable. Rotate it in stages instead, each deployed to every instance, worker, and CLI configuration before the next begins:

1. **Introduce:** keep the old `secret` and add the new value to `previousSecrets` (at most five). Every process can now open values sealed with either, while still sealing with the old one. Give downstream verifiers `iam.assertionKeys()`, which lists both assertion keys; `verifyAssertion`, the NestJS assertion module, and the Next.js edge verifier accept a list.
2. **Switch:** make the new value `secret` and move the old one to `previousSecrets`. New values are sealed with the new secret, and old values and pending links keep working.
3. **Re-seal:** run `better-iam rotate-secrets` (`iam.rotateSecrets()`). It re-seals stored authenticator secrets, webhook secrets, and pending payloads with the new secret in short transactions and prints what it changed. `--dry-run` only counts. Repeat until it reports `done: true`.
4. **Retire:** a day later, when emailed links and assertions issued under the old secret have expired, remove `previousSecrets` everywhere. Configure downstream verifiers with `iam.assertionKey()` alone. If the old secret leaked, retire it as soon as `done: true`, and never hand its assertion key to new verifiers.

`doctor` shows where the rotation stands:

- `secret-rotation-pending` while stored values still need the old secret;
- `secret-rotation-unverified` when its sample did not cover every record (confirm with `rotate-secrets --dry-run`);
- `previous-secrets-configured` when `previousSecrets` can go.

Configurations created by `better-iam init` read `previousSecrets` from `BETTER_IAM_PREVIOUS_SECRETS` (comma-separated), as the console does. Keys an application derives from `secret` itself need the same treatment. The console, for example, derives its outbound SCIM provisioner's `encryptionKey` from it. Pass the keys derived from `previousSecrets` as the provisioner's `previousEncryptionKeys`, then call `provisioner.rotateKeys()`, which re-seals stored downstream tokens and reports `{ resealed, current, unreadable }`.

It reports the error `unreadable-secrets` when stored values open with no configured secret, which is what happens when the secret was replaced without `previousSecrets`. The fix is to put the old secret back into `previousSecrets` and rotate. `rotate-secrets` exits non-zero (`UNREADABLE_SECRETS`) in the same case.

## Temporary credentials

The `sts` option configures role sessions, session tokens, session JWTs, and web-identity federation; [temporary credentials](temporary-credentials.md) explains the flows. Every value is validated when `betterIam()` runs, and a bad one throws `INVALID_CONFIG` naming the field.

```ts
sts: {
  maxRoleSessionSeconds: 3600, // 900..43200; trusts can only lower it
  maxSessionTokenSeconds: 43200, // 900..129600
  maxSessionTokensPerIdentity: 50, // 1..1000 live session tokens per identity
  jwt: {
    signingKeys: [JSON.parse(process.env.IAM_SESSION_JWK!)], // Ed25519/EdDSA or P-256/ES256 private JWKs with a kid
    verificationKeys: [], // public halves of retired keys, during a rotation
    audiences: ['https://billing.example.com'], // services that verify tokens; the issuer is always allowed
    maxLifetimeSeconds: 900, // 300..43200 (default 3600); keep it short, offline verifiers see revocation only at exp
  },
  webIdentity: {
    enabled: true, // off by default
    allowedIssuers: ['https://token.actions.githubusercontent.com'], // optional deployment-wide pin
  },
},
```

- **Session JWT keys** (`sts.jwt`): 1 to 10 private signing JWKs, `activeKeyId` (default the first), 0 to 10 public-only `verificationKeys`, `issuer` (default `${baseURL.origin}${basePath}`), `audiences`, and `maxLifetimeSeconds`. They are not derived from `secret`, so secret rotation never touches them, and they are separate from the OAuth provider's keys. Keep them in your secret store. Rotate by adding the new key, waiting at least the JWKS cache time plus your verifiers' cache (15 minutes with the defaults), switching `activeKeyId`, moving the old public key to `verificationKeys`, and removing it after `maxLifetimeSeconds`. Removing a `kid` from both lists revokes every token it signed, inside IAM at once.
- **JWKS route:** `GET {basePath}/.well-known/jwks.json` serves the public keys with `Cache-Control: public, max-age=300` and `Content-Type: application/jwk-set+json` (404 without `sts.jwt`); `iam.sessionTokens.jwks()` returns the same set. CDNs may cache it for the same five minutes; the rotation wait above assumes that.
- **Web identity** (`sts.webIdentity`): `enabled`, `allowedIssuers` (at most 100), `jwksCacheSeconds` (600; 60..3600), `fetchTimeoutMs` (5000; 500..10000), `maxJwksBytes` (65536; 1024..1048576), `maxExchangesPerWindow` (600 per trust per `authentication.rateLimits.windowMs`), `maxSessionsPerTrust` (1000), and for development only `allowPrivateNetworks` and `allowInsecureLocalhost`. Provider keys are fetched from the server with an SSRF guard (public addresses, https on port 443, no redirects, size and time caps). If your servers reach the internet only through an egress proxy, supply `fetchJson(url)` with your own transport; it bypasses the guard, so it must enforce the same rules. The exchange writes one rate-limiter row per trust id it is called with, so also set `authentication.rateLimits.ipAttempts` behind `http.clientInfo`, and apply ingress limits to `POST {basePath}/sts/assumeRoleWithWebIdentity`.
- **Retention:** `sweep` deletes expired session tokens and redeemed web-identity token records; derived sessions whose source ended stay unusable until then.
- **Monitoring:** subscribe to `role:assumed`, `role:assumed-with-web-identity` (watch `deny` spikes), `session-token:issued`, and `role:sessions-revoked`; `better_iam_sessions_live{kind}` (with `observability.metrics.gauges`) counts live session tokens and role sessions.

## Protocol mounts

Use `iam.useProtocol(service)` followed by `iam.nodeHandler` for the complete server. The OAuth issuer requires Node HTTP interfaces. Application-owned interaction handlers must validate origin/CSRF, authenticate actual IAM credentials, and display login/consent/device/logout screens. See [protocols](protocols.md) and the examples.

## Build and publication

```sh
pnpm check
pnpm pack:all
node scripts/packed-smoke.mjs
```

`scripts/release-version.mjs VERSION` updates synchronized package versions. Update the changelog, reinstall to refresh the lockfile, and rerun checks. Packed package tests install all tarballs into a fresh consumer and verify exports, native dependencies, migrations, and bootstrap.

All packages are Apache-2.0 licensed and publish publicly to npm (`publishConfig.access: public`). Releases are published by the `publish` job in `.github/workflows/ci.yml`: after every green push to `main` (all test matrix jobs and the PostgreSQL job), it publishes with `pnpm publish -r --provenance` when the package version is not on npm yet, then tags `vX.Y.Z` and creates a GitHub release. Pushes that keep the version publish nothing, so a release is cut by bumping the version with `scripts/release-version.mjs`. The workflow needs an `NPM_TOKEN` repository secret (an npm automation or granular token with publish rights on `better-iam` and the `@better-iam` scope). Pre-release versions (`1.2.0-beta.0`) publish under the `next` dist-tag.

## PostgreSQL integration checks

Set `BETTER_IAM_POSTGRES_URL` to an isolated test database and run `pnpm test:postgres`. Tests use namespaced records and separate pools. The adapter conformance suite gives each case its own schema when the server honors the connection `options` parameter, and falls back to per-case collection prefixes otherwise. `BETTER_IAM_POSTGRES_POOL_SIZE` sets its pool size (default 3). The normal suite explicitly skips PostgreSQL-only cases when the variable is absent; CI runs a dedicated PostgreSQL service job.
