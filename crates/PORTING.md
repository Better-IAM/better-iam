# Porting the server modules to Rust

This guide is for the agents (and people) who fill in the Rust server skeleton in `crates/server`. Read
`spec/BUILDOUT.md` first for the parity contract. The TypeScript source under `packages/server/src` is the
specification: port it line by line, with the same validation order, error codes, messages and statuses, defaults,
record shapes (camelCase JSON) and audit event names.

## Where things are

| TypeScript                                | Rust                                                     |
| ----------------------------------------- | -------------------------------------------------------- |
| `packages/server/src/<module>.ts`         | `crates/server/src/<module>.rs` (`-` becomes `_`)        |
| `packages/server/src/api/<file>.ts`       | `crates/server/src/api/<file>.rs`                        |
| `betterIam(options)` (index.ts)           | `index.rs` `better_iam(options) -> BetterIam`            |
| `createApi` (api/index.ts)                | `api/index.rs` `create_api` / `Api` (one field per group) |
| the router of http.ts                     | `http.rs` + the generated table `api/dispatch.rs`        |
| interfaces of the attached services       | `contracts.rs` (traits)                                  |
| `scripts/conformance/serve.mjs`           | `conformance.rs` + `src/bin/better-iam-server.rs`        |

Ported in full: `decisions`, `operations`, `principals`, `http`, `index`, `api/index`, `api/filters`, `agreements`,
`usage`, `hosts` (with `createHosts`), the `actions`, `resourceTypes`, `audit`, `authorities`, `credentials`, `links`
and `root` API groups, `lifecycle` (`initialize`, `bootstrap`, `recoverRoot`, `pruneAudit`), and kernel A
(`options`, `models`, `context`, `catalog`, `events`, `observe`, `metrics`, `validation`, `assertions`, `guarded`,
`secrets`, ...). Everything else is a skeleton.

### Files that are final

Do not edit these to make your module work; if you believe one needs a change, report it instead:
`lib.rs`, `api/mod.rs`, `api/index.rs`, `api/dispatch.rs` (generated), `http.rs`, `index.rs`, `conformance.rs`,
`contracts.rs`, `decisions.rs`, `operations.rs`, `principals.rs`, `bin/better-iam-server.rs`. The router already
reaches every route of `spec/api/routes.json` (`tests/route_manifest.rs` proves it), the composition root already
constructs every runtime, and the conformance server already forwards every `call` to the runtime that owns it.

## The skeleton

`crates/server/tools/gen-skeleton.mjs` generated one file per TypeScript module with a stub for every exported item
another module imports, translated from the TypeScript signature by the TypeScript checker. Every stub returns

```rust
Err(not_ported("teams.ts teamChain"))        // IamError NOT_IMPLEMENTED, status 501
```

To port a module: replace each stub body with the port of the TypeScript function, remove the
`//! SKELETON ...` paragraph and the `#![allow(unused_variables, ...)]` line once nothing is a stub any more, and add
the module's private helpers. Keep the signatures: other modules (and the final files) already call them. Things to
know about the generated code:

- **Types.** `string` → `String` / `&str`, `number` → `f64`, `T | undefined` → `Option<T>`, arrays → `Vec<T>` /
  `&[T]`, `Set<string>` → `IndexSet<String>`, `Map` → `IndexMap`, `unknown` parameters → `Option<&Value>` (validate
  them as TypeScript does), records → the structs of `models.rs` or `better_iam_core`. Types the generator could not
  translate are `Value` (`TODO(port)` marks the declarations). A stub's signature may be refined when you port it
  (a `Value` placeholder becoming a struct, `IamResult<T>` becoming `T` for a function that cannot fail) as long as
  you update its callers in the same change; search for the function name across `crates/server/src`.
- **Interfaces with methods** were generated as empty structs marked `TODO(port)`; give them their Rust form (a
  trait, or a struct of closures). `MandatoryAccess` (clearances.rs) shows the pattern.
- **Factories** (`createXRuntime(ctx)`, `createRetention(ctx)`, ...) are structs holding `Arc<ServerContext>` with
  one method per member of the object TypeScript returns, plus `call(&self, method, args) -> Option<IamResult<Value>>`,
  the conformance server's entry (CONTROL.md `call`). When you port a member, make its `call` arm decode the JSON
  arguments and call the typed method; return `crate::port::undefined()` for members that return nothing.
- **Error classes** (`QuotaExceededError`, `SdJwtError`, ...) became structs; give them a real constructor and an
  `impl From<X> for IamError`. Details TypeScript errors carry (`retryAfterMs`, `WRONG_REGION`'s `region` and
  `location`) go through `crate::port::with_details(error, ErrorDetails { .. })`; the HTTP layer and the
  conformance server read them back.

## API groups

Each API group is a struct (`TenantsApi`) with one method per route:

```rust
pub async fn create(
    &self,
    credential: &CredentialInput,                 // absent for publicApiMethods
    input: Body<tenants::CreateInput>,            // the request body as TypeScript receives `input`
) -> IamResult<Reply<tenants::CreateOutput>>
```

- `Body<I>` derefs to the raw JSON object (`input.get("name")`). Validate members yourself, in the TypeScript order,
  with `crate::validation` (`text`, `text256`, `integer`, `object`, `strings`, `email`), which produce the TypeScript
  messages. `input.decode()` reads the body as the generated request type once validation has passed.
- Answer `Reply::json(value)` with the JSON the TypeScript returns, built in its member order (serde_json keeps
  insertion order), or `Reply::from(typed)` with the generated result type. Numbers: `crate::js::number(f64)`
  (JavaScript formatting: `1`, not `1.0`). `undefined` members are left out.
- `crate::api::string_member(&input, "tenantId")` gives the resource ID of operations that authorize on a member
  (`operation(credential, input.tenantId, action, input.identityId, ...)`); a non-string value becomes `""`, which
  the envelope refuses exactly as TypeScript refuses the non-string.
- `crate::api::credential_from_json` reads a credential given in a body (`targetCredential`).

### The operation envelope

```rust
let ctx = &self.ctx;
let body = &input;
let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, tenant }| {
    Box::pin(async move {
        ctx.auth.require_recent(&principal)?;               // `?` turns IamError into OperationFailure
        if forbidden {
            return Err(OperationDenied::new(Some("Cannot ...")));   // rolled back, audited as deny, 403
        }
        let record = ctx.scoped(&tx, "roles", body.get("roleId"), &tenant.id).await?;
        ...
        Ok(json!({ "deleted": true }))
    })
});
let result = ctx
    .operations()?
    .operation(credential, input.get("tenantId"), "iam:roles:delete", &crate::api::string_member(&input, "roleId"), mutation, false)
    .await?;
Ok(Reply::json(result))
```

`operation` authenticates, re-validates the principal, authorizes `action` on `iam/{resourceId}`, runs the
separation-of-duties and invariant checks, the plugin hooks, the mutation, and appends the audit event (allow, or
deny on refusal); it records access usage after the commit. `root_only` is the TypeScript `rootOnly` flag. The mutation
may borrow from the method (`ctx`, `body`).

## Storage, records, clocks, audit

- Writes happen inside `ctx.store.transaction(|tx| async move { ... })` (`better_iam_core::IamStoreExt`); nested
  transactions join the outer one. Reads outside a transaction are allowed.
- Records are JSON objects (`better_iam_core::Record`). For read-modify-write, keep the raw record, change members
  with `insert`/`shift_remove` and `put` it back, so member order and members you do not know survive (a mixed fleet
  shares the database with TypeScript). Build new records as a `Map` in the TypeScript insertion order. Read typed
  values with `crate::port::decode::<T>(record)` (STORAGE_CORRUPT for a malformed record).
- `ctx.now()` is the injected clock (`ctx.now()` / `authentication.now()` in TypeScript); `crate::utils::date_now()`
  is `Date.now()`. Use the one the TypeScript line uses: the conformance server controls both separately.
- Audit: `ctx.events()?.audit(&tx, &principal, action, tenant_id, resource_id, AuditOutcome::Allow, root_override,
  metadata)` or `record_audit(&tx, &event_record)` for system events (`actorId: 'deployment-operator'`).
- Context: `ctx.options` (typed options; `crate::options_value::options_value(&ctx.options)` is the JSON the
  TypeScript validators see), `ctx.config`, `ctx.catalog`, `ctx.auth`, and the attached services `ctx.decisions()?`,
  `ctx.principals()?`, `ctx.operations()?`, `ctx.flows()?`, `ctx.usage()?`, `ctx.hosts()?`, `ctx.events()?`.
- Decisions read module context lazily through the providers you own: `agent_decision_scope` (agents), `guest_context`
  / `guest_boundary` (guests), `agreement_context`, `onboarding_context`, `team_context`, `department_context`,
  `BillingService::spend_context`, `consent_context`, `license_context`, `risk_context`, `device_context`,
  `clearance_scope` / `attach_label` / `scheme_for_tenant` / `labels_for_type` (clearances), and the resource
  resolvers `resolve_secret_resource`, `resolve_model_resource`, `resolve_ssh_resource`,
  `resolve_credential_type_resource`. Their `mentions_*` guards and the "module off" paths are ported, so a stub only
  answers 501 when a document names the module's keys or the module is enabled; porting the stub activates it.

## Tests

- Port the TypeScript tests of your module into `crates/server/tests/<module>.rs`. `tests/kernel_b.rs` shows the
  harness: a fixture built with `better_iam(options)` on an in-memory SQLite store, `run(|| async { ... })` (a runtime
  on a thread with a 64 MiB stack: debug-build futures are large), store writes inside transactions, HTTP requests
  through `iam.handler`.
- Run: `export PATH="$HOME/.cargo/bin:$PATH"`, then `cargo fmt --all`, `cargo clippy --workspace --all-targets --
  -D warnings`, `cargo test -p better-iam-server`. Use your own `CARGO_TARGET_DIR` when other agents build at the same
  time.

## The replay runner

The conformance suite replays the traces recorded from the TypeScript tests against the Rust server:

```sh
cargo build -p better-iam-server --bin better-iam-server
node scripts/conformance/replay.mjs \
  --server '"<target>/debug/better-iam-server.exe" --conformance --config {config} --port {port}' \
  --filter group:<apiGroup> --jobs 4 --json report.json
```

`--filter group:roles` selects the traces that call that group (most traces create a tenant first, so they stop at
`tenants/create` until the `tenants` group is ported); `--filter <text>` matches trace ids and files; `--keep-going`
replays past the first failing step; `--dump <dir>` writes the recorded and actual answers of failing steps. The
summary lists replayed steps per API group (`auth 3369/3369 ok`) and the reasons traces are not replayable. A step
that answers `NOT_IMPLEMENTED` names the stub to port next.

## Fidelity checklist

- Same validation order and messages (`text(value, 'name', 128)` → `text(input.get("name"), "name", 128)`), same
  `IamError` code, message and status, same defaults and limits.
- Same records: collection names, member names, member order of new records, `uniqueKey` formats.
- Same audit events: action names, outcomes, metadata members.
- No silent gaps: what you cannot finish stays `Err(not_ported(..))` and is reported.
