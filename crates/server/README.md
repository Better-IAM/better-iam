# better-iam-server

The [Better IAM](https://github.com/Better-IAM/better-iam) server for Rust, the counterpart of the `@better-iam/server`
npm package. It shares its database with the TypeScript implementation: TypeScript and Rust servers can serve one
deployment from one SQLite, PostgreSQL or libSQL database.

The crate mirrors `packages/server/src` module for module:

- **Composition** (`better_iam`, the TypeScript `betterIam(options)`): configuration and catalog validation, the
  authentication service, the shared context, the service modules, the provisioning API, deployment operations
  (`initialize`, `bootstrap`, `recover_root`, `prune_audit`, ...) and the HTTP transports.
- **The decision engine** (`decisions`): grants from bindings, groups, roles, attached and inherited policies and the
  authorities that issued them, bounded by tenant boundaries, agent and delegation scopes, principal boundaries,
  session policies and credential authorities, with relationship tuples and the server-derived context keys.
- **The operation envelope** (`operations`): authenticate, re-validate, authorize, mutate, audit, in one transaction;
  `authorize`, `authorize_many`, `list_accessible` and plugin endpoints.
- **Credential resolution** (`principals`): user sessions, API keys, role sessions, session tokens, delegated sessions
  and IAM-signed session JWTs, each re-validated on use.
- **HTTP** (`http`): the router of every route in `spec/api/routes.json`, the CSRF boundary, cookies, CORS, host
  pinning, the operational GET routes and protocol mounts; a framework-neutral `handler` (`http::Request<Bytes>` in,
  `http::Response<Bytes>` out) and a `tower::Service` (`http::HttpService`).
- **The kernel**: options, records, validation, the permission catalog, chained audit events and webhooks,
  observability and metrics, assertions, the guarded envelope and secret rotation.

Modules not ported yet answer `NOT_IMPLEMENTED` (501); `crates/PORTING.md` in the repository describes how they are
filled in.

## The standalone server

```sh
better-iam-server --config better-iam.json --port 4100 [--host 127.0.0.1] [--conformance]
```

reads the JSON configuration of `spec/conformance/CONFIG.md`. With `--conformance` it also answers the test-control
endpoints of `spec/conformance/CONTROL.md`, which the repository's replay runner drives.

```rust,ignore
use better_iam_server::{better_iam, options::BetterIamOptions};

let iam = better_iam(BetterIamOptions::new(store, secret, "https://iam.example.com"))?;
iam.initialize().await?;
let response = iam.handler(request).await;
```

Licensed under Apache-2.0.
