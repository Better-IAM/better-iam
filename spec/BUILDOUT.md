# better-iam in Rust and Go: buildout plan

Status: in progress on branch `rust-go-port` (started 2026-10-19).

## Goal

Ship native Rust and Go implementations of better-iam from this repository, at parity with the
TypeScript (Node) implementation, published to crates.io, the Go module proxy, and npm in lockstep.

"Parity" (1:1) means, concretely and measurably:

1. **Same HTTP surface.** Every route the TypeScript server answers (`POST {basePath}/{group}/{method}`,
   `auth/*`, `authorize`, `authorizeMany`, `listAccessible`, `plugins/*`, the operational `GET` routes,
   the OAuth/OIDC, SAML, SCIM, LDAP, OpenID4VCI, SSF protocol mounts) exists in the Rust and Go servers with
   the same request/response JSON, the same `IamError` codes and HTTP statuses, cookies, CORS and CSRF rules.
2. **Same database (mixed fleet).** All three servers read and write the same SQLite/Postgres/libSQL schema
   and the same record shapes per collection, so TypeScript, Rust, and Go replicas can run side by side on one
   database, and a deployment can move between them without data conversion. Password hashes, sealed
   secrets, token hashes, the audit hash chain, session JWTs, assertions, and delegation tokens are
   byte-compatible.
3. **Same behavior.** The decision engine, policies, conditions, validation, limits, and every API group
   behave identically, proven by replaying traces recorded from the TypeScript test suite against each port.
4. **Same tools.** A `better-iam` CLI with the same commands and flags, a typed API client, and server
   middleware for each language's mainstream web frameworks.

Out of scope for the ports (they stay TypeScript-only because they bind JavaScript UI frameworks): `react`,
`vue`, `svelte`, `next`, `nuxt`, `nestjs`, `react-router`, the console app and the docs site. Their server-side
role is covered in Rust and Go by native framework middleware (below).

## Repository layout

TypeScript stays where it is (no path churn for the published npm packages, CI, the Dockerfile, or the docs
generator). Rust and Go get their own roots, and a language-neutral `spec/` holds the contract all three meet.

```
better-iam/
├─ spec/                     language-neutral contract (generated from TypeScript, checked in)
│  ├─ BUILDOUT.md            this plan
│  ├─ api/routes.json        every route: group, method, public/authenticated, tenant-bound, cookies
│  ├─ api/errors.json        IamError codes → HTTP status
│  ├─ catalog/actions.json   built-in actions and resource types
│  ├─ storage/collections.json  collections, indexed/ordered/expiry fields, unique keys
│  ├─ storage/migrations/{sqlite,postgres}/NNNN_name.sql
│  ├─ vectors/*.json         crypto and format test vectors (JCS, audit chain, sealing, hashes, JWTs…)
│  └─ conformance/           recorded API traces + the replay format description
├─ packages/  apps/  examples/   TypeScript (unchanged)
├─ Cargo.toml                Cargo workspace root (members = crates/*)
├─ crates/                   Rust crates (one per npm package that ports)
├─ go/                       Go module github.com/Better-IAM/better-iam/go
├─ scripts/spec/             generators that write spec/ from the TypeScript sources
├─ scripts/conformance/      standalone TS server, trace recorder, replay runner
└─ .github/workflows/        ci.yml (TS), rust.yml, go.yml, conformance.yml, release.yml
```

## Package map

| npm                         | crates.io                       | Go package (`github.com/Better-IAM/better-iam/go/...`) |
| --------------------------- | ------------------------------- | ------------------------------------------------------ |
| `@better-iam/core`          | `better-iam-core`               | `core`                                                 |
| `@better-iam/adapter-sqlite`   | `better-iam-adapter-sqlite`  | `adapters/sqlite`                                      |
| `@better-iam/adapter-postgres` | `better-iam-adapter-postgres`| `adapters/postgres`                                    |
| `@better-iam/adapter-libsql`   | `better-iam-adapter-libsql`  | `adapters/libsql`                                      |
| `@better-iam/auth`          | `better-iam-auth`               | `auth`                                                 |
| `@better-iam/server`        | `better-iam-server`             | `server` (+ `server/api`)                              |
| `@better-iam/oauth`         | `better-iam-oauth`              | `oauth`                                                |
| `@better-iam/saml`          | `better-iam-saml`               | `saml`                                                 |
| `@better-iam/scim`          | `better-iam-scim`               | `scim`                                                 |
| `@better-iam/ldap`          | `better-iam-ldap`               | `ldap`                                                 |
| `@better-iam/client`        | `better-iam-client`             | `client`                                               |
| `@better-iam/projects`      | `better-iam-projects`           | `projects`                                             |
| `@better-iam/middleware`    | `better-iam-middleware` (tower, axum, actix-web features) | `middleware` (+ `middleware/chi`, `gin`, `echo`) |
| `@better-iam/mcp`           | `better-iam-mcp`                | `mcp`                                                  |
| `@better-iam/a2a`           | `better-iam-a2a`                | `a2a`                                                  |
| `@better-iam/cli`           | `better-iam-cli` (binary `better-iam`) | `cmd/better-iam`                                |
| `better-iam` (umbrella)     | `better-iam` (re-exports, feature-gated) | `iam` (umbrella import)                       |

## Language conventions

**Rust.** Edition 2024, MSRV pinned in the workspace. `tokio` runtime; `serde`/`serde_json` with a
`Record = serde_json::Value`-backed store contract identical to `IamStore`; `thiserror` `IamError { code,
message, status }`. HTTP on `hyper` 1 / `http` types so the handler is framework-neutral (`tower::Service`);
axum and actix-web adapters live in `better-iam-middleware`. Storage: `rusqlite` (bundled) on a blocking pool,
`tokio-postgres`, `libsql`. Crypto from RustCrypto (`argon2`, `sha2`, `hmac`, `aes-gcm`, `p256`, `ed25519-dalek`,
`rsa`), `rustls` for TLS. No OpenSSL dependency anywhere.

**Go.** Go 1.24+ minimum. Standard library `net/http` (`http.Handler`), `database/sql` with `modernc.org/sqlite`
(pure Go, no cgo), `jackc/pgx/v5`, `tursodatabase/libsql-client-go`; `golang.org/x/crypto` (argon2, ed25519,
ssh). `context.Context` first on every call; errors are `*core.IamError` with `Code`, `Message`, `Status`.

**Both.** Module and file names mirror the TypeScript modules (`decisions.ts` → `decisions.rs` /
`decisions.go`), so a change in one implementation is easy to find in the others. Options mirror
`BetterIamOptions` field-for-field; JavaScript callbacks become traits (Rust) / interfaces or func fields (Go)
with the same names. Every port also reads a JSON config file (`better-iam.json`) for the standalone server,
which is how the conformance suite starts all three.

## Parity verification

Five layers, all run in CI:

1. **Route manifest.** `spec/api/routes.json` is generated from the TypeScript route table. Each port has a
   test that its router answers exactly that set (no missing, no extra routes).
2. **Store conformance.** `@better-iam/core`'s `adapterConformanceCases()` is ported case-for-case; every
   Rust and Go adapter must pass it.
3. **Vectors.** `spec/vectors/*.json` are produced by the TypeScript implementation (JCS canonicalization,
   audit chain hashes, deployment-secret sealing, token hashing, assertion HMACs, session JWTs, delegation
   tokens, password-hash verification, SCIM filter parsing, policy evaluation cases). Ports must reproduce or
   verify every vector.
4. **Trace replay.** A recorder wraps the TypeScript API during `vitest run` and writes each test's API calls
   (credential, group, method, input, result or error, captured outbox messages, clock moves) to
   `spec/conformance/traces/`. A replay runner starts any server from `better-iam.json` and replays the trace
   over HTTP, binding generated IDs and tokens by position and comparing normalized responses. The
   TypeScript server replaying its own traces is the calibration baseline; parity is reported per API group.
5. **Mixed fleet.** One database, three servers: records written by each are read, updated, and audited by
   the others (sessions issued by one validate on another; the audit chain verifies across writers).

### Running the mixed fleet

The store-level checks (`scripts/conformance/fleet/sqlite-fleet.mjs`, `go-fleet.mjs`) share one database file between
the adapters. The server-level check, `scripts/conformance/fleet/servers.mjs`, starts the TypeScript, Rust and Go
servers in conformance mode at the same time on one SQLite file (WAL), with the same `better-iam.json` (deployment
secret, base URL, trusted origin, session JWT signing key), and walks one scenario across them over HTTP. Each step
goes to the next server in rotation and the answers are checked on the others: bootstrap and a refused second
bootstrap; root sign-in, TOTP enrollment and confirmation on three different servers; a tenant created on one, its
owner invitation delivered by another and accepted on a third; identities, a role and a binding, with the same
`authorize` decisions everywhere; a session cookie and bearer issued by one used on the others; an API key and a
session JWT (verified against every server's JWKS) issued on one, accepted on all; the same identity updated from
each server in turn; a vault secret sealed on one and revealed on another; concurrent writes from all three; an API
key, a signed-out cookie and revoked sessions (with their JWT) refused everywhere; and finally every server reads the
same audit log and `audit/verify` passes for each tenant.

```sh
pnpm build                                                     # the TypeScript packages
cargo build -p better-iam-server --bin better-iam-server       # target/debug/better-iam-server
(cd go && go build -o ../target/go/better-iam-server ./cmd/better-iam-server)
node scripts/conformance/fleet/servers.mjs                     # [--only ts,go] [--keep] [--verbose]
```

`--rust <bin>`, `--go <bin>` and `--ts-root <dir>` (or `FLEET_RUST_BIN`, `FLEET_GO_BIN`, `FLEET_TS_ROOT`) point at
binaries and a built checkout elsewhere. It prints PASS/FAIL per step with the servers it used, names the server whose
answer differed (and the JSON paths that differ), exits 1 on any failure, and keeps the database, configuration and
server logs of a failed run.

## Versioning and publishing

All three ecosystems ship one version number in lockstep. `node scripts/release-version.mjs X.Y.Z` bumps every
`package.json`, the Cargo workspace version (and internal crate dependency versions), and `go/version.go`.

- **npm** — unchanged: `ci.yml` publishes with provenance after a green push to `main` whose version is not on
  npm yet.
- **crates.io** — `release.yml` runs `cargo publish --workspace` (dependency order handled by Cargo) after
  Rust CI passes. The first publish of each crate needs a `CARGO_REGISTRY_TOKEN` secret; afterwards each crate is
  switched to crates.io trusted publishing (GitHub OIDC via `rust-lang/crates-io-auth-action`) and the token is
  removed. Already-published versions are skipped so a rerun finishes a partial release.
- **Go** — Go modules publish by tag. Because the module lives in `go/`, the tag is `go/vX.Y.Z` (the root
  `vX.Y.Z` tag stays the repository/npm release). The release job pushes the tag and asks
  `proxy.golang.org` for the version so it is indexed immediately. While the version is `0.x`, no `/vN`
  import suffix is needed.
- **GitHub release** — one release `vX.Y.Z` with notes, created after all three registries succeed; Rust and Go
  CLI binaries for linux/macOS/windows (amd64, arm64) are attached.

One-time prerequisites (repository owner): a crates.io account that owns the `better-iam*` crate names and the
`CARGO_REGISTRY_TOKEN` secret for the first release; nothing extra for Go; `NPM_TOKEN` as today.

## Execution phases

Each phase runs as a multi-agent workflow; the result is reviewed before the next one starts.

1. **Contract** — generators for `spec/` (routes, errors, catalog, collections, migrations, vectors); the
   standalone TypeScript conformance server, the trace recorder, and the replay runner, calibrated against the
   TypeScript server itself.
2. **Foundations** (Rust and Go in parallel, sequential within each language) — core + adapters + store
   conformance + vectors → auth → server kernel A (options, models, context, catalog, events, observe, metrics,
   validation) → server kernel B (decisions, operations, principals, HTTP router, composition) with a stub for
   every route and every cross-module function, so later work only fills in bodies.
3. **Fan-out** — every remaining server module and API group, plus `oauth`, `saml`, `scim`, `ldap`, `client`,
   `projects`, `middleware`, `mcp`, `a2a`, ported per language in its own git worktree and branch, each with a
   fidelity review against the TypeScript source; branches merge back into `rust-go-port`.
4. **Integration** — the CLI and umbrella packages; trace replay and mixed-fleet runs; a fix loop per failing
   API group until the ports match the TypeScript baseline.
5. **Release plumbing** — CI workflows, release orchestration, package metadata, docs pages for Rust and Go.

## Risks

- **OIDC provider.** The TypeScript `oauth` package sits on `oidc-provider`; neither ecosystem has an equivalent,
  so the provider is implemented natively in both ports, limited to the features the TypeScript configuration
  enables, and verified by the protocol traces.
- **SAML XML signatures.** Canonicalization and signature validation are implemented without libxml2/xmlsec in
  Rust; both ports get dedicated signature-wrapping and comment-injection tests.
- **WebAuthn.** Attestation/assertion verification is implemented on RustCrypto (Rust) and `go-webauthn` (Go)
  and checked against the existing TypeScript passkey fixtures.
- **Scale.** About 160k lines of TypeScript (113k in the server) per port. Drift is controlled by the shared
  spec, module-for-module file mapping, and the replay suite in CI: a change that lands in one implementation
  without the others fails conformance.
